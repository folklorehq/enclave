import { Buffer } from 'node:buffer';
import { Hono } from 'hono';
import type { EnclaveRuntimeEvidence } from '@folklore/contracts/enclave-attestation';

export const RUNTIME_ATTESTATION_CHALLENGE_PATH = '/challenge';

export type RuntimeAttestationFetchHandler = (request: Request) => Response | Promise<Response>;

export interface RuntimeAttestationEvidenceCollector {
  collect(nonce: Uint8Array): Promise<EnclaveRuntimeEvidence>;
  sign?(payload: Uint8Array): { publicKey: Uint8Array; signature: Uint8Array };
  sessionPublicKey?(): Uint8Array;
}

export interface RuntimeAttestationListener {
  listen(handler: RuntimeAttestationFetchHandler): void | Promise<void>;
}

export interface RuntimeAttestationServerOptions {
  maxBodyBytes?: number;
  rateLimit?: RuntimeAttestationRateLimitOptions;
  clock?: RuntimeAttestationClock;
}

export interface RuntimeAttestationRateLimitOptions {
  maxRequests: number;
  windowMs: number;
}

export interface RuntimeAttestationClock {
  now(): number;
}

type RuntimeAttestationErrorCode =
  | 'runtime_attestation_body_too_large'
  | 'runtime_attestation_failed'
  | 'runtime_attestation_in_progress'
  | 'runtime_attestation_invalid_nonce'
  | 'runtime_attestation_invalid_request'
  | 'runtime_attestation_manifest_changed'
  | 'runtime_attestation_not_found'
  | 'runtime_attestation_not_ready'
  | 'runtime_attestation_rate_limited'
  | 'runtime_attestation_replayed_nonce';

type RequestBodyRead =
  | { ok: true; text: string }
  | { ok: false; error: 'runtime_attestation_body_too_large' };

const ATTESTATION_NONCE_BYTES = 32;
const ATTESTATION_NONCE_BASE64_LENGTH = 44;
const ATTESTATION_NONCE_BASE64_PATTERN = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const DEFAULT_MAX_BODY_BYTES = 256;
const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 60;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
const JSON_CONTENT_TYPE = 'application/json';
const REQUEST_NONCE_KEY = 'nonce';

const ERROR_STATUS: Record<RuntimeAttestationErrorCode, number> = {
  runtime_attestation_body_too_large: 413,
  runtime_attestation_failed: 500,
  runtime_attestation_in_progress: 409,
  runtime_attestation_invalid_nonce: 400,
  runtime_attestation_invalid_request: 400,
  runtime_attestation_manifest_changed: 503,
  runtime_attestation_not_found: 404,
  runtime_attestation_not_ready: 503,
  runtime_attestation_rate_limited: 429,
  runtime_attestation_replayed_nonce: 409,
};

const RUNTIME_ATTESTATION_ERROR_CODES = new Set<RuntimeAttestationErrorCode>(
  Object.keys(ERROR_STATUS) as RuntimeAttestationErrorCode[],
);

export class RuntimeAttestationServer {
  private readonly app = new Hono();
  private readonly maxBodyBytes: number;
  private readonly rateLimit: RuntimeAttestationRateLimitOptions;
  private readonly clock: RuntimeAttestationClock;
  private windowStartedAt = 0;
  private requestsInWindow = 0;

  constructor(
    private readonly collector: RuntimeAttestationEvidenceCollector,
    options: RuntimeAttestationServerOptions = {},
  ) {
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    this.rateLimit = options.rateLimit ?? {
      maxRequests: DEFAULT_RATE_LIMIT_MAX_REQUESTS,
      windowMs: DEFAULT_RATE_LIMIT_WINDOW_MS,
    };
    this.clock = options.clock ?? { now: () => Date.now() };
    this.app.post(RUNTIME_ATTESTATION_CHALLENGE_PATH, (context) =>
      this.answerChallenge(context.req.raw),
    );
    this.app.notFound(() => this.errorResponse('runtime_attestation_not_found'));
    this.app.onError(() => this.errorResponse('runtime_attestation_failed'));
  }

  async start(listener: RuntimeAttestationListener): Promise<void> {
    await listener.listen((request) => this.handleRequest(request));
  }

  handleRequest(request: Request): Promise<Response> {
    return Promise.resolve(this.app.fetch(request));
  }

  private async answerChallenge(request: Request): Promise<Response> {
    if (!this.takeRateLimitToken()) {
      return this.errorResponse('runtime_attestation_rate_limited');
    }
    const body = await this.readBody(request);
    if (!body.ok) return this.errorResponse(body.error);
    const nonce = this.decodeNonce(body.text);
    if (nonce === undefined) return this.errorResponse('runtime_attestation_invalid_request');
    if (nonce === null) return this.errorResponse('runtime_attestation_invalid_nonce');
    try {
      const evidence = await this.collector.collect(nonce);
      return this.jsonResponse(evidence, 200);
    } catch (error: unknown) {
      return this.errorResponse(this.errorCodeFrom(error));
    }
  }

  private takeRateLimitToken(): boolean {
    const now = this.clock.now();
    if (now - this.windowStartedAt >= this.rateLimit.windowMs) {
      this.windowStartedAt = now;
      this.requestsInWindow = 0;
    }
    if (this.requestsInWindow >= this.rateLimit.maxRequests) return false;
    this.requestsInWindow += 1;
    return true;
  }

  private async readBody(request: Request): Promise<RequestBodyRead> {
    const contentLength = this.contentLength(request);
    if (contentLength !== undefined && contentLength > this.maxBodyBytes) {
      return { ok: false, error: 'runtime_attestation_body_too_large' };
    }
    const reader = request.body?.getReader();
    if (reader === undefined) return { ok: true, text: '' };
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    while (true) {
      const read = await reader.read();
      if (read.done) break;
      bytes += read.value.byteLength;
      if (bytes > this.maxBodyBytes) {
        await reader.cancel();
        return { ok: false, error: 'runtime_attestation_body_too_large' };
      }
      chunks.push(read.value);
    }
    return { ok: true, text: Buffer.concat(chunks).toString('utf8') };
  }

  private contentLength(request: Request): number | undefined {
    const header = request.headers.get('content-length');
    if (header === null) return undefined;
    const parsed = Number.parseInt(header, 10);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
  }

  private decodeNonce(text: string): Uint8Array | undefined | null {
    const body = this.parseJson(text);
    if (!isRecord(body)) return undefined;
    const keys = Object.keys(body);
    if (keys.length !== 1 || keys[0] !== REQUEST_NONCE_KEY) return undefined;
    const nonce = body[REQUEST_NONCE_KEY];
    if (typeof nonce !== 'string') return undefined;
    if (
      nonce.length !== ATTESTATION_NONCE_BASE64_LENGTH ||
      !ATTESTATION_NONCE_BASE64_PATTERN.test(nonce)
    ) {
      return null;
    }
    const decoded = Buffer.from(nonce, 'base64');
    return decoded.byteLength === ATTESTATION_NONCE_BYTES ? decoded : null;
  }

  private parseJson(text: string): unknown {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return undefined;
    }
  }

  private errorCodeFrom(error: unknown): RuntimeAttestationErrorCode {
    if (error instanceof Error && this.isRuntimeAttestationCode(error.message)) {
      return error.message;
    }
    return 'runtime_attestation_failed';
  }

  private isRuntimeAttestationCode(value: string): value is RuntimeAttestationErrorCode {
    return RUNTIME_ATTESTATION_ERROR_CODES.has(value as RuntimeAttestationErrorCode);
  }

  private errorResponse(error: RuntimeAttestationErrorCode): Response {
    return this.jsonResponse({ error }, ERROR_STATUS[error]);
  }

  private jsonResponse(body: unknown, status: number): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': JSON_CONTENT_TYPE },
    });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
