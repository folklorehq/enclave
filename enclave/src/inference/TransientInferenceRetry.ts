export const TRANSIENT_INFERENCE_ATTEMPTS = 3;
const BACKOFF_BASE_MS = 250;
const MAX_CAUSE_DEPTH = 8;
const TRANSIENT_PROVIDER_STATUS =
  /^OpenAI-compatible endpoint (?:embed|generate|tool call|stream) failed: 50[234]$/;
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

export interface TransientInferenceRetryDeps {
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

/** Re-runs one inference operation through a provider gateway blip; every other refusal fails on its first throw. */
export class TransientInferenceRetry {
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;

  constructor(deps: TransientInferenceRetryDeps = {}) {
    this.sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.random = deps.random ?? Math.random;
  }

  async run<T>(operation: () => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await operation();
      } catch (error: unknown) {
        if (attempt >= TRANSIENT_INFERENCE_ATTEMPTS || !this.isTransient(error)) throw error;
        await this.sleep(this.backoffMs(attempt));
      }
    }
  }

  private backoffMs(attempt: number): number {
    return Math.floor(BACKOFF_BASE_MS * 2 ** (attempt - 1) * (1 + this.random()));
  }

  // Only a gateway status, a timeout or a dropped connection; a 4xx, a 500 or a verification refusal is final.
  private isTransient(error: unknown): boolean {
    let current = error;
    for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
      if (this.isTransientLink(current)) return true;
      current = current.cause;
    }
    return false;
  }

  private isTransientLink(error: Error): boolean {
    if (error instanceof DOMException) return error.name === TIMEOUT_ERROR;
    if (TRANSIENT_PROVIDER_STATUS.test(error.message) || error.message === OPERATION_DEADLINE) {
      return true;
    }
    const code = (error as Error & { code?: unknown }).code;
    return typeof code === 'string' && TRANSIENT_NETWORK_CODES.has(code);
  }
}
