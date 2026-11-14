import { z } from 'zod';
import { parseRetryAfterMs } from '@folklore/utils';
import { ANTHROPIC_ORIGIN } from '../../egress/anthropic-transport.js';
import { ANTHROPIC_API_VERSION, claudeIdentityMismatch } from './ClaudeCredentialSource.js';
import type { ClaudeRequestBody } from './claude-request.js';
import { BATCH_RESULT_LINE_MAX_BYTES } from './batch-limits.js';
import { BatchResultLineSplitter } from './BatchResultLineSplitter.js';
import { BatchResultsGuard } from './BatchResultsGuard.js';
import type { BatchResultRefusal } from './batch-log.js';
import { ClaudeRouteError } from './claude-route-errors.js';

const BATCHES_PATH = '/v1/messages/batches';
const BATCH_ID = /^msgbatch_[A-Za-z0-9]{1,64}$/;
const ERROR_TYPE = /^[a-z_]{1,64}$/;
const UNKNOWN_ERROR_TYPE = 'unknown';
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_RETRY_AFTER_MS = 60_000;
const HTTP_OK = 200;
const HTTP_BAD_REQUEST = 400;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const HTTP_NOT_FOUND = 404;
const HTTP_CONFLICT = 409;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_SERVER_ERROR = 500;
const NO_STATUS: ReadonlySet<number> = new Set();

export type BatchProcessingStatus = 'in_progress' | 'canceling' | 'ended' | 'gone';
/** `gone`: someone else deleted it first; `refused`: it still exists. */
export type BatchDeleteOutcome = 'deleted' | 'gone' | 'refused';

export interface BatchCreateItem {
  readonly custom_id: string;
  readonly params: ClaudeRequestBody;
}

export type BatchResultLine =
  | { readonly customId: string; readonly outcome: 'succeeded'; readonly message: unknown }
  | { readonly customId: string; readonly outcome: 'errored'; readonly errorType: string }
  | { readonly customId: string; readonly outcome: 'canceled' | 'expired' };

export interface BatchApiDeps {
  readonly fetch: typeof globalThis.fetch;
  readonly apiKey: () => Promise<string>;
  readonly expected: {
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
  };
  readonly onIdentityMismatch: () => void;
  readonly onCredentialRejected: () => void;
}

export interface BatchResultsRead {
  readonly maxBytes: number;
  readonly budgetMs: number;
  readonly signal?: AbortSignal;
  readonly onRefused: (
    reason: Extract<BatchResultRefusal, 'malformed' | 'oversize_line' | 'oversize_body'>,
  ) => void;
  readonly onCut?: () => void;
}

const createdSchema = z.object({ id: z.string().regex(BATCH_ID) });
const statusSchema = z.object({ processing_status: z.enum(['in_progress', 'canceling', 'ended']) });
const lineSchema = z.object({
  custom_id: z.string().min(1).max(64),
  result: z.object({ type: z.enum(['succeeded', 'errored', 'canceled', 'expired']) }).passthrough(),
});

/** The Message Batches calls of one workspace, each response bound to the compiled workspace before it is read. */
export class BatchApiClient {
  constructor(private readonly deps: BatchApiDeps) {
    if (deps.expected.workspaceIdSha256 === '') {
      throw new ClaudeRouteError('claude_batch_identity_unset');
    }
  }

  async create(items: readonly BatchCreateItem[]): Promise<string> {
    const response = await this.call('POST', BATCHES_PATH, { body: { requests: items } });
    const parsed = createdSchema.safeParse(await this.json(response));
    if (!parsed.success) throw new ClaudeRouteError('claude_batch_response_invalid');
    return parsed.data.id;
  }

  async status(batchId: string): Promise<BatchProcessingStatus> {
    const response = await this.call('GET', this.pathOf(batchId), { tolerate: [HTTP_NOT_FOUND] });
    if (response.status === HTTP_NOT_FOUND) return 'gone';
    const parsed = statusSchema.safeParse(await this.json(response));
    if (!parsed.success) throw new ClaudeRouteError('claude_batch_response_invalid');
    return parsed.data.processing_status;
  }

  async *results(batchId: string, read: BatchResultsRead): AsyncGenerator<BatchResultLine> {
    read.signal?.throwIfAborted();
    const guard = new BatchResultsGuard(read, REQUEST_TIMEOUT_MS);
    try {
      const response = await this.openResults(batchId, guard, read.signal);
      if (response === undefined) return;
      guard.bodyStarted();
      yield* this.linesOf(response, read, guard);
    } finally {
      guard.dispose();
    }
  }

  async cancel(batchId: string): Promise<void> {
    const tolerate = [HTTP_BAD_REQUEST, HTTP_NOT_FOUND, HTTP_CONFLICT];
    const response = await this.call('POST', `${this.pathOf(batchId)}/cancel`, { tolerate });
    await response.body?.cancel().catch(() => undefined);
  }

  async delete(batchId: string): Promise<BatchDeleteOutcome> {
    const tolerate = [HTTP_BAD_REQUEST, HTTP_NOT_FOUND, HTTP_CONFLICT];
    const response = await this.call('DELETE', this.pathOf(batchId), { tolerate });
    await response.body?.cancel().catch(() => undefined);
    if (response.status === HTTP_OK) return 'deleted';
    return response.status === HTTP_NOT_FOUND ? 'gone' : 'refused';
  }

  private pathOf(batchId: string): string {
    if (!BATCH_ID.test(batchId)) throw new ClaudeRouteError('claude_batch_response_invalid');
    return `${BATCHES_PATH}/${batchId}`;
  }

  private async call(
    method: string,
    path: string,
    options: { body?: unknown; tolerate?: readonly number[]; signal?: AbortSignal } = {},
  ): Promise<Response> {
    const key = await this.deps.apiKey();
    const response = await this.send(method, path, key, options.body, options.signal);
    this.assertStatus(response, new Set(options.tolerate ?? NO_STATUS));
    return response;
  }

  private async send(
    method: string,
    path: string,
    key: string,
    body: unknown,
    signal: AbortSignal = AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  ): Promise<Response> {
    try {
      return await this.deps.fetch(`${ANTHROPIC_ORIGIN}${path}`, {
        method,
        headers: {
          'x-api-key': key,
          'anthropic-version': ANTHROPIC_API_VERSION,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal,
      });
    } catch {
      throw new ClaudeRouteError('claude_batch_unavailable');
    }
  }

  private assertStatus(response: Response, tolerated: ReadonlySet<number>): void {
    const { status } = response;
    if (status === HTTP_UNAUTHORIZED || status === HTTP_FORBIDDEN) {
      this.deps.onCredentialRejected();
      throw new ClaudeRouteError('claude_credential_rejected');
    }
    this.assertBound(response.headers);
    if (status === HTTP_OK || tolerated.has(status)) return;
    if (status === HTTP_TOO_MANY_REQUESTS) throw this.rateLimited(response);
    if (status >= HTTP_SERVER_ERROR) throw new ClaudeRouteError('claude_batch_unavailable');
    throw new ClaudeRouteError('claude_batch_request_invalid');
  }

  private assertBound(headers: Pick<Headers, 'get'>): void {
    const mismatch = claudeIdentityMismatch(headers, this.deps.expected);
    if (mismatch === undefined) return;
    this.deps.onIdentityMismatch();
    throw new ClaudeRouteError(mismatch);
  }

  private rateLimited(response: Response): ClaudeRouteError {
    const retryAfterMs = parseRetryAfterMs(
      response.headers.get('retry-after'),
      Date.now(),
      MAX_RETRY_AFTER_MS,
    );
    return new ClaudeRouteError('claude_rate_limited', HTTP_TOO_MANY_REQUESTS, retryAfterMs);
  }

  private async json(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new ClaudeRouteError('claude_batch_response_invalid');
    }
  }

  private async openResults(
    batchId: string,
    guard: BatchResultsGuard,
    signal: AbortSignal | undefined,
  ): Promise<Response | undefined> {
    guard.awaitingHeaders();
    try {
      const path = `${this.pathOf(batchId)}/results`;
      const response = await this.call('GET', path, {
        tolerate: [HTTP_NOT_FOUND],
        signal: guard.signal,
      });
      return response.status === HTTP_NOT_FOUND ? undefined : response;
    } catch (error) {
      if (signal?.aborted === true) throw signal.reason;
      throw error;
    }
  }

  private async *linesOf(
    response: Response,
    read: BatchResultsRead,
    guard: BatchResultsGuard,
  ): AsyncGenerator<BatchResultLine> {
    if (Number(response.headers.get('content-length')) > read.maxBytes) {
      await response.body?.cancel().catch(() => undefined);
      read.onRefused('oversize_body');
      return;
    }
    const reader = response.body?.getReader();
    if (reader === undefined) return;
    const splitter = new BatchResultLineSplitter(BATCH_RESULT_LINE_MAX_BYTES, () =>
      read.onRefused('oversize_line'),
    );
    let total = 0;
    try {
      for (;;) {
        const next = await guard.next(reader);
        if (next.done) break;
        const usable = next.value.subarray(0, read.maxBytes - total);
        total += usable.byteLength;
        yield* this.parsed(splitter.feed(usable), read);
        if (usable.byteLength < next.value.byteLength) {
          read.onRefused('oversize_body');
          return;
        }
      }
      yield* this.parsed(splitter.last(), read);
    } finally {
      await reader.cancel().catch(() => undefined);
    }
  }

  private *parsed(lines: Iterable<Buffer>, read: BatchResultsRead): Generator<BatchResultLine> {
    for (const bytes of lines) {
      const text = bytes.toString('utf8');
      if (text.trim() === '') continue;
      const line = this.lineOf(text);
      if (line === undefined) read.onRefused('malformed');
      else yield line;
    }
  }

  private lineOf(line: string): BatchResultLine | undefined {
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      return undefined;
    }
    const parsed = lineSchema.safeParse(value);
    if (!parsed.success) return undefined;
    const { custom_id: customId, result } = parsed.data;
    if (result.type === 'succeeded')
      return { customId, outcome: 'succeeded', message: result['message'] };
    if (result.type === 'errored') {
      return { customId, outcome: 'errored', errorType: this.errorTypeOf(result['error']) };
    }
    return { customId, outcome: result.type };
  }

  private errorTypeOf(error: unknown): string {
    const inner = (error as { error?: { type?: unknown } } | undefined)?.error?.type;
    const outer = (error as { type?: unknown } | undefined)?.type;
    const type = typeof inner === 'string' ? inner : outer;
    return typeof type === 'string' && ERROR_TYPE.test(type) ? type : UNKNOWN_ERROR_TYPE;
  }
}
