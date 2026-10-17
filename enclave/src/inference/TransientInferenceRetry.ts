import { ProviderHttpError } from '@folklore/inference';

export const TRANSIENT_INFERENCE_ATTEMPTS = 3;
const BACKOFF_BASE_MS = 250;
const MAX_CAUSE_DEPTH = 8;
const HTTP_TOO_MANY_REQUESTS = 429;
// Callers told the same Retry-After must not all return on the same tick.
export const RETRY_AFTER_SPREAD_MS = 1_000;
const TRANSIENT_PROVIDER_STATUSES: ReadonlySet<number> = new Set([
  HTTP_TOO_MANY_REQUESTS,
  502,
  503,
  504,
]);
const OPERATION_DEADLINE = 'public_aci_operation_deadline';
const TIMEOUT_ERROR = 'TimeoutError';
const TRANSIENT_NETWORK_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'ETIMEDOUT',
  'EPIPE',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
]);

export interface TransientRetryWindows {
  readonly retryMs: number;
  readonly rateLimitMs: number;
}

const UNBOUNDED_WINDOWS: TransientRetryWindows = Object.freeze({
  retryMs: Number.POSITIVE_INFINITY,
  rateLimitMs: Number.POSITIVE_INFINITY,
});

export type BackoffObserver = (backoff: () => Promise<void>) => Promise<void>;

const UNOBSERVED: BackoffObserver = (backoff) => backoff();

export interface TransientInferenceRetryDeps {
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  now?: () => number;
}

/** Re-runs one inference operation through a provider gateway blip or rate limit; every other refusal fails on its first throw. */
export class TransientInferenceRetry {
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;
  private readonly now: () => number;

  constructor(deps: TransientInferenceRetryDeps = {}) {
    this.sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.random = deps.random ?? Math.random;
    this.now = deps.now ?? (() => performance.now());
  }

  /** A failure past `retryMs`, or a rate-limit wait ending past `rateLimitMs`, from the first attempt is final. */
  async run<T>(
    operation: () => Promise<T>,
    windows: TransientRetryWindows = UNBOUNDED_WINDOWS,
    observeBackoff: BackoffObserver = UNOBSERVED,
    transientStatuses: ReadonlySet<number> = TRANSIENT_PROVIDER_STATUSES,
  ): Promise<T> {
    const startedAt = this.now();
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await operation();
      } catch (error: unknown) {
        const delayMs = this.retryDelayMs(
          error,
          attempt,
          this.now() - startedAt,
          windows,
          transientStatuses,
        );
        if (delayMs === undefined) throw error;
        await observeBackoff(() => this.sleep(delayMs));
      }
    }
  }

  private retryDelayMs(
    error: unknown,
    attempt: number,
    elapsedMs: number,
    windows: TransientRetryWindows,
    transientStatuses: ReadonlySet<number>,
  ): number | undefined {
    if (attempt >= TRANSIENT_INFERENCE_ATTEMPTS || elapsedMs >= windows.retryMs) return undefined;
    const transient = this.transientLink(error, transientStatuses);
    if (!transient) return undefined;
    const backoffMs = this.backoffMs(attempt);
    if (!this.isRateLimit(transient)) return backoffMs;
    const delayMs = this.rateLimitDelayMs(backoffMs, transient.retryAfterMs);
    // A wait that outlasts the window is handed back to queue redelivery instead of spent here.
    return elapsedMs + delayMs < Math.min(windows.retryMs, windows.rateLimitMs)
      ? delayMs
      : undefined;
  }

  private rateLimitDelayMs(backoffMs: number, retryAfterMs: number | undefined): number {
    if (retryAfterMs === undefined) return backoffMs;
    return Math.max(backoffMs, retryAfterMs + Math.floor(RETRY_AFTER_SPREAD_MS * this.random()));
  }

  private backoffMs(attempt: number): number {
    return Math.floor(BACKOFF_BASE_MS * 2 ** (attempt - 1) * (1 + this.random()));
  }

  private isRateLimit(error: Error): error is ProviderHttpError {
    return error instanceof ProviderHttpError && error.status === HTTP_TOO_MANY_REQUESTS;
  }

  // Only a gateway status, a rate limit, a timeout or a dropped connection; any other 4xx, a 500 or a verification refusal is final.
  private transientLink(error: unknown, transientStatuses: ReadonlySet<number>): Error | undefined {
    let current = error;
    for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
      if (this.isTransientLink(current, transientStatuses)) return current;
      current = current.cause;
    }
    return undefined;
  }

  private isTransientLink(error: Error, transientStatuses: ReadonlySet<number>): boolean {
    if (error instanceof DOMException) return error.name === TIMEOUT_ERROR;
    if (error instanceof ProviderHttpError) return transientStatuses.has(error.status);
    if (error.message === OPERATION_DEADLINE) return true;
    const code = (error as Error & { code?: unknown }).code;
    return typeof code === 'string' && TRANSIENT_NETWORK_CODES.has(code);
  }
}
