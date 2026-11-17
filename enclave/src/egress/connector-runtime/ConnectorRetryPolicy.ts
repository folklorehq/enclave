import { ConnectorSpecError } from '@folklore/errors';
import type { ConnectorRuntimeLog, ConnectorRuntimeLogFields } from './ConnectorRuntimeLog.js';

const CONNECTOR_RETRY_STATUSES = [408, 429, 500, 502, 503, 504] as const;
const CONNECTOR_RETRY_NETWORK_CODES = [
  'ECONNRESET',
  'ETIMEDOUT',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
] as const;
const CONNECTOR_MAX_RETRIES = 3;
const CONNECTOR_MAX_RETRY_WAIT_MS = 30_000;

const BASE_BACKOFF_MS = 1000;
const MS_PER_SECOND = 1000;
const WAIT_BUCKETS = [0, 1000, 5000, 30000] as const;

interface RetryDeps {
  readonly sleep: (ms: number) => Promise<void>;
  readonly nowMs: () => number;
  readonly log: ConnectorRuntimeLog;
}

interface RetryMeta {
  readonly kind: string;
  readonly stream: string;
}

type RetryDetail = Pick<ConnectorRuntimeLogFields, 'httpStatus' | 'errorCode'>;

export class ConnectorRetryPolicy {
  constructor(private readonly deps: RetryDeps) {}

  async run(meta: RetryMeta, attempt: () => Promise<Response>): Promise<Response> {
    for (let retries = 0; ; retries += 1) {
      let response: Response;
      try {
        response = await attempt();
      } catch (error) {
        if (error instanceof ConnectorSpecError) throw error;
        const code = ConnectorRetryPolicy.networkCodeOf(error);
        if (code === undefined || retries >= CONNECTOR_MAX_RETRIES) {
          throw new ConnectorSpecError('egress_request_failed');
        }
        await this.wait(meta, retries, ConnectorRetryPolicy.backoffMs(retries), {
          errorCode: code.toLowerCase(),
        });
        continue;
      }
      if (
        !ConnectorRetryPolicy.isRetryableStatus(response.status) ||
        retries >= CONNECTOR_MAX_RETRIES
      )
        return response;
      const waitMs = this.statusWaitMs(response, retries);
      await response.body?.cancel();
      await this.wait(meta, retries, waitMs, { httpStatus: response.status });
    }
  }

  private statusWaitMs(response: Response, retries: number): number {
    const advised = this.retryAfterMs(response.headers.get('retry-after'));
    return Math.min(
      advised ?? ConnectorRetryPolicy.backoffMs(retries),
      CONNECTOR_MAX_RETRY_WAIT_MS,
    );
  }

  private retryAfterMs(value: string | null): number | null {
    if (value === null) return null;
    if (/^\d{1,9}$/.test(value)) return Number(value) * MS_PER_SECOND;
    const at = Date.parse(value);
    return Number.isNaN(at) ? null : Math.max(0, at - this.deps.nowMs());
  }

  private async wait(
    meta: RetryMeta,
    retries: number,
    waitMs: number,
    detail: RetryDetail,
  ): Promise<void> {
    this.deps.log.retry({
      component: meta.kind,
      operation: `${meta.stream}:send`,
      attempt: retries + 1,
      durationMs: ConnectorRetryPolicy.bucketOf(waitMs),
      ...detail,
    });
    await this.deps.sleep(waitMs);
  }

  private static backoffMs(retries: number): number {
    return Math.min(BASE_BACKOFF_MS * 2 ** retries, CONNECTOR_MAX_RETRY_WAIT_MS);
  }

  private static isRetryableStatus(status: number): boolean {
    return (CONNECTOR_RETRY_STATUSES as readonly number[]).includes(status);
  }

  private static bucketOf(waitMs: number): ConnectorRuntimeLogFields['durationMs'] {
    return WAIT_BUCKETS.find((bucket) => waitMs <= bucket) ?? 30000;
  }

  private static networkCodeOf(error: unknown): string | undefined {
    for (const link of [error, (error as { cause?: unknown } | null)?.cause]) {
      const code = (link as { code?: unknown } | null | undefined)?.code;
      if ((CONNECTOR_RETRY_NETWORK_CODES as readonly unknown[]).includes(code))
        return code as string;
    }
    return undefined;
  }
}
