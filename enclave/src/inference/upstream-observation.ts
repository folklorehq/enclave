import { AsyncLocalStorage } from 'node:async_hooks';
import { parseRetryAfterMs } from '@folklore/utils';

export const MAX_PROVIDER_PAUSE_MS = 60_000;
export const NEAR_LIMIT_FRACTION = 0.1;

const ANTHROPIC_FAMILIES = ['requests', 'tokens', 'input-tokens', 'output-tokens'] as const;
const OPENAI_FAMILIES = ['requests', 'tokens'] as const;
const COUNT = /^\d{1,12}$/;
const RFC_3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const DURATION = /^(?:\d+(?:\.\d+)?(?:ms|h|m|s))+$/;
const DURATION_PART = /(\d+(?:\.\d+)?)(ms|h|m|s)/g;
const DURATION_UNIT_MS: Readonly<Record<string, number>> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
};
const TIMEOUT_ERROR = 'TimeoutError';

export interface ProviderRateHint {
  /** Some family reports none remaining. */
  readonly exhausted: boolean;
  /** Some family reports remaining < limit × NEAR_LIMIT_FRACTION. */
  readonly nearLimit: boolean;
  /** retry-after when present, else the latest reset of an exhausted family, minus now; clamped [0, MAX_PROVIDER_PAUSE_MS]. */
  readonly pauseMs?: number;
}

export interface UpstreamResponseObservation {
  readonly status: number;
  readonly requestMs: number;
  readonly hint?: ProviderRateHint;
}

export interface UpstreamCallObserver {
  responded(observation: UpstreamResponseObservation): void;
  timedOut(): void;
  /** A classified provider limit (spend cap, workspace limit): one decrease per epoch and a pause. */
  limitReached(pauseMs: number): void;
  usage(promptTokens: number, completionTokens: number): void;
}

export class UpstreamObservationScope {
  private readonly storage = new AsyncLocalStorage<UpstreamCallObserver>();

  run<T>(observer: UpstreamCallObserver, fn: () => Promise<T>): Promise<T> {
    return this.storage.run(observer, fn);
  }

  current(): UpstreamCallObserver | undefined {
    return this.storage.getStore();
  }
}

export const upstreamObservationScope = new UpstreamObservationScope();

interface FamilyReading {
  readonly limit: number | undefined;
  readonly remaining: number | undefined;
  readonly resetMs: number | undefined;
}

export function readProviderRateHint(
  headers: Pick<Headers, 'get'>,
  nowMs: number,
): ProviderRateHint | undefined {
  const families = [
    ...ANTHROPIC_FAMILIES.map((family) => anthropicFamily(headers, family, nowMs)),
    ...OPENAI_FAMILIES.map((family) => openAiFamily(headers, family)),
  ];
  const retryAfterMs = parseRetryAfterMs(headers.get('retry-after'), nowMs, MAX_PROVIDER_PAUSE_MS);
  const reported = families.filter((family) => family.remaining !== undefined);
  if (reported.length === 0 && retryAfterMs === undefined) return undefined;
  const exhausted = reported.filter((family) => family.remaining === 0);
  const pauseMs = retryAfterMs ?? latestReset(exhausted);
  return {
    exhausted: exhausted.length > 0,
    nearLimit: reported.some((family) => isNearLimit(family)),
    ...(pauseMs === undefined ? {} : { pauseMs }),
  };
}

export function observeUpstreamFetch(
  fetchImpl: typeof fetch,
  isInferenceRequest: (url: URL, init?: RequestInit) => boolean,
  now: () => number = () => performance.now(),
): typeof fetch {
  return async (input, init) => {
    const observer = upstreamObservationScope.current();
    if (observer === undefined || !isObserved(input, init, isInferenceRequest)) {
      return fetchImpl(input, init);
    }
    const startedAt = now();
    let response: Response;
    try {
      response = await fetchImpl(input, init);
    } catch (error: unknown) {
      if (isTimeout(error)) safely(() => observer.timedOut());
      throw error;
    }
    const hint = readProviderRateHint(response.headers, Date.now());
    const requestMs = now() - startedAt;
    safely(() =>
      observer.responded({
        status: response.status,
        requestMs,
        ...(hint === undefined ? {} : { hint }),
      }),
    );
    return response;
  };
}

export function reportUpstreamTimeout(): void {
  safely(() => upstreamObservationScope.current()?.timedOut());
}

export function reportUpstreamLimitReached(pauseMs: number): void {
  safely(() => upstreamObservationScope.current()?.limitReached(pauseMs));
}

export function reportUpstreamUsage(promptTokens: number, completionTokens: number): void {
  safely(() => upstreamObservationScope.current()?.usage(promptTokens, completionTokens));
}

function safely(report: () => void): void {
  try {
    report();
  } catch {
    // An observer must never change what the call returns or throws.
  }
}

function isTimeout(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && 'name' in error && error.name === TIMEOUT_ERROR
  );
}

function isObserved(
  input: Parameters<typeof fetch>[0],
  init: RequestInit | undefined,
  isInferenceRequest: (url: URL, init?: RequestInit) => boolean,
): boolean {
  try {
    const supplied =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    return isInferenceRequest(new URL(supplied), init);
  } catch {
    return false;
  }
}

function count(value: string | null): number | undefined {
  return value !== null && COUNT.test(value) ? Number(value) : undefined;
}

function anthropicFamily(
  headers: Pick<Headers, 'get'>,
  family: string,
  nowMs: number,
): FamilyReading {
  const prefix = `anthropic-ratelimit-${family}`;
  const reset = headers.get(`${prefix}-reset`);
  const at = reset !== null && RFC_3339.test(reset) ? Date.parse(reset) : Number.NaN;
  return {
    limit: count(headers.get(`${prefix}-limit`)),
    remaining: count(headers.get(`${prefix}-remaining`)),
    resetMs: Number.isNaN(at) ? undefined : at - nowMs,
  };
}

function openAiFamily(headers: Pick<Headers, 'get'>, family: string): FamilyReading {
  return {
    limit: count(headers.get(`x-ratelimit-limit-${family}`)),
    remaining: count(headers.get(`x-ratelimit-remaining-${family}`)),
    resetMs: durationMs(headers.get(`x-ratelimit-reset-${family}`)),
  };
}

function durationMs(value: string | null): number | undefined {
  if (value === null || !DURATION.test(value)) return undefined;
  let total = 0;
  for (const part of value.matchAll(DURATION_PART)) {
    total += Number(part[1]) * (DURATION_UNIT_MS[part[2] ?? ''] ?? 0);
  }
  return total;
}

function isNearLimit(family: FamilyReading): boolean {
  return (
    family.remaining !== undefined &&
    family.limit !== undefined &&
    family.remaining < family.limit * NEAR_LIMIT_FRACTION
  );
}

function latestReset(exhausted: readonly FamilyReading[]): number | undefined {
  const resets = exhausted.flatMap((family) =>
    family.resetMs === undefined ? [] : [family.resetMs],
  );
  if (resets.length === 0) return undefined;
  return Math.min(Math.max(...resets, 0), MAX_PROVIDER_PAUSE_MS);
}
