import { CONNECTOR_MANIFESTS, FORBIDDEN_HEADER, type ConnectorManifest } from '@folklore/contracts';
import type {
  ConnectorTransport,
  Logger,
  TransportRequest,
  TransportResponse,
} from '@folklore/core';
import { ConnectorSpecError, isAppError, type ConnectorSpecErrorCode } from '@folklore/errors';
import { ProxyAgent } from 'undici';
import { EGRESS_PROXY_URL } from '../proxy.js';
import { BufferedTransportResponse } from './BufferedTransportResponse.js';
import { ConnectorConcurrency } from './ConnectorConcurrency.js';
import { ConnectorRetryPolicy } from './ConnectorRetryPolicy.js';
import { ConnectorRuntimeLog } from './ConnectorRuntimeLog.js';
import { readLimitedBody } from './response-limits.js';

export interface ConnectorEgressTransportInput {
  readonly kind: string;
  readonly orgId: string;
  readonly token: string;
  readonly logger: Logger;
  readonly concurrency?: ConnectorConcurrency;
  readonly fetchImpl?: typeof globalThis.fetch;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly nowMs?: () => number;
}

type FetchImpl = typeof globalThis.fetch;

const REQUEST_TIMEOUT_MS = 30_000;
const SUCCESS_STATUS_MIN = 200;
const REDIRECT_STATUS_MIN = 300;
const CLIENT_ERROR_STATUS_MIN = 400;
const JSON_MEDIA_TYPE = 'application/json';
const CREDENTIAL_HEADER = 'authorization';
const MANIFESTS: readonly ConnectorManifest[] = CONNECTOR_MANIFESTS;
const defaultConcurrency = new ConnectorConcurrency();

export class ConnectorEgressTransport implements ConnectorTransport {
  private readonly manifest: ConnectorManifest | undefined;
  private readonly concurrency: ConnectorConcurrency;
  private readonly log: ConnectorRuntimeLog;
  private readonly retry: ConnectorRetryPolicy;

  constructor(private readonly input: ConnectorEgressTransportInput) {
    this.manifest = MANIFESTS.find((candidate) => candidate.kind === input.kind);
    this.concurrency = input.concurrency ?? defaultConcurrency;
    this.log = new ConnectorRuntimeLog(input.logger);
    this.retry = new ConnectorRetryPolicy({
      sleep: input.sleep ?? ConnectorEgressTransport.sleepFor,
      nowMs: input.nowMs ?? Date.now,
      log: this.log,
    });
  }

  async send(request: TransportRequest): Promise<TransportResponse> {
    const target = this.allowedTarget(request);
    const headers = this.headersFor(request);
    return this.concurrency.run(this.input.orgId, this.input.kind, () =>
      this.exchange(request, target, headers),
    );
  }

  private allowedTarget(request: TransportRequest): URL {
    const target = ConnectorEgressTransport.parseUrl(request.url);
    const hosts = this.manifest?.egress.apiHosts ?? [];
    if (
      target === null ||
      !ConnectorEgressTransport.isPlainHttps(target) ||
      !hosts.includes(target.hostname)
    ) {
      throw this.refuse('egress_host_refused', `${request.stream}:send`, 1);
    }
    return target;
  }

  // The spec can name headers but never the credential: Authorization comes from the auth mode alone.
  private headersFor(request: TransportRequest): Headers {
    this.assertSpecHeadersAllowed(request);
    try {
      const headers = new Headers(request.headers);
      headers.set('accept', JSON_MEDIA_TYPE);
      if (request.body !== null && !headers.has('content-type')) {
        headers.set('content-type', JSON_MEDIA_TYPE);
      }
      headers.delete(CREDENTIAL_HEADER);
      if (request.auth === 'bearer') headers.set(CREDENTIAL_HEADER, `Bearer ${this.input.token}`);
      if (request.auth === 'raw_token') headers.set(CREDENTIAL_HEADER, this.input.token);
      return headers;
    } catch {
      throw new ConnectorSpecError('header_value_refused');
    }
  }

  // The manifest schema bans these names too; a spec that skipped it must not reach the wire.
  private assertSpecHeadersAllowed(request: TransportRequest): void {
    const owned = Object.keys(request.headers).some(
      (name) => name.toLowerCase() !== CREDENTIAL_HEADER && FORBIDDEN_HEADER.test(name),
    );
    if (owned) throw this.refuse('header_value_refused', `${request.stream}:send`, 1);
  }

  private async exchange(
    request: TransportRequest,
    target: URL,
    headers: Headers,
  ): Promise<TransportResponse> {
    const read = async (fetchImpl: FetchImpl) => {
      let attempts = 0;
      const response = await this.retry.run(
        { kind: this.input.kind, stream: request.stream },
        () => {
          attempts += 1;
          return this.attempt(fetchImpl, { request, target, headers, attempt: attempts });
        },
      );
      return this.buffered(response);
    };
    if (this.input.fetchImpl) return read(this.input.fetchImpl);
    return this.withProxiedFetch(read);
  }

  private async attempt(
    fetchImpl: FetchImpl,
    sent: { request: TransportRequest; target: URL; headers: Headers; attempt: number },
  ): Promise<Response> {
    const { request, target, headers } = sent;
    const response = await this.fetchOnce(fetchImpl, target, {
      method: request.method,
      headers,
      ...(request.body === null ? {} : { body: request.body }),
    });
    if (!ConnectorEgressTransport.isRedirect(response.status)) return response;
    await response.body?.cancel();
    return this.followRedirect(fetchImpl, sent, response);
  }

  private async followRedirect(
    fetchImpl: FetchImpl,
    sent: { request: TransportRequest; target: URL; attempt: number },
    redirect: Response,
  ): Promise<Response> {
    const operation = `${sent.request.stream}:redirect`;
    const next = this.redirectTarget(sent.request, sent.target, redirect.headers.get('location'));
    if (next === null) {
      throw this.refuse('egress_redirect_refused', operation, sent.attempt, redirect.status);
    }
    const hop = await this.fetchOnce(fetchImpl, next, {
      method: 'GET',
      headers: new Headers({ accept: JSON_MEDIA_TYPE }),
    });
    if (!ConnectorEgressTransport.isRedirect(hop.status)) return hop;
    await hop.body?.cancel();
    throw this.refuse('egress_redirect_refused', operation, sent.attempt, hop.status);
  }

  // One GET hop, to the same origin or a declared CDN suffix; the caller sends it without the credential.
  private redirectTarget(
    request: TransportRequest,
    from: URL,
    location: string | null,
  ): URL | null {
    const suffixes = this.manifest?.egress.cdnSuffixes ?? [];
    if (request.method !== 'GET' || suffixes.length === 0 || location === null) return null;
    const next = ConnectorEgressTransport.parseUrl(location, from);
    if (next === null || !ConnectorEgressTransport.isPlainHttps(next)) return null;
    const onCdn = suffixes.some((suffix) => next.hostname.endsWith(suffix));
    return next.origin === from.origin || onCdn ? next : null;
  }

  private fetchOnce(fetchImpl: FetchImpl, url: URL, init: RequestInit): Promise<Response> {
    return fetchImpl(url.href, {
      ...init,
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  }

  private async buffered(response: Response): Promise<TransportResponse> {
    if (response.status < SUCCESS_STATUS_MIN || response.status >= REDIRECT_STATUS_MIN) {
      await response.body?.cancel();
      return new BufferedTransportResponse(response.status, response.headers, '');
    }
    try {
      return new BufferedTransportResponse(
        response.status,
        response.headers,
        await readLimitedBody(response),
      );
    } catch (error) {
      throw isAppError(error) ? error : new ConnectorSpecError('egress_request_failed');
    }
  }

  // Non-pooled on purpose: each send dials through its own CONNECT tunnel and closes it.
  private async withProxiedFetch<T>(use: (fetchImpl: FetchImpl) => Promise<T>): Promise<T> {
    const dispatcher = new ProxyAgent({ uri: EGRESS_PROXY_URL });
    const proxied = ((input, init) =>
      globalThis.fetch(input, { ...init, dispatcher } as RequestInit)) as FetchImpl;
    try {
      return await use(proxied);
    } finally {
      await dispatcher.close().catch(() => undefined);
    }
  }

  private refuse(
    code: ConnectorSpecErrorCode,
    operation: string,
    attempt: number,
    httpStatus?: number,
  ): ConnectorSpecError {
    this.log.refused({
      component: this.input.kind,
      operation,
      attempt,
      durationMs: 0,
      errorCode: code,
      ...(httpStatus === undefined ? {} : { httpStatus }),
    });
    return new ConnectorSpecError(code);
  }

  private static parseUrl(value: URL | string, base?: URL): URL | null {
    try {
      return new URL(value, base);
    } catch {
      return null;
    }
  }

  private static isPlainHttps(url: URL): boolean {
    return (
      url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === ''
    );
  }

  private static isRedirect(status: number): boolean {
    return status >= REDIRECT_STATUS_MIN && status < CLIENT_ERROR_STATUS_MIN;
  }

  private static sleepFor(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
