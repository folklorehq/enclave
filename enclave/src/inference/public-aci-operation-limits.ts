import type { InferenceModelRole } from '@folklore/contracts';
import type { TransientRetryWindows } from './TransientInferenceRetry.js';

export type InferenceLatencyProfile = 'batch' | 'interactive';

export interface PublicAciOperationLimits {
  readonly requestTimeoutMs: number;
  readonly operationBudgetMs: number;
  readonly checkpointAgeMs: number;
}

// The operation budget keeps ten seconds of headroom below the NSM checkpoint age it is bound to.
const CHECKPOINT_HEADROOM_MS = 10_000;
const SHORT_REQUEST_TIMEOUT_MS = 40_000;
const SHORT_OPERATION_BUDGET_MS = 50_000;
// 8192 output tokens at a sustained ~50 tokens/s is ~165 s of decode before the prompt is counted.
const LONG_REQUEST_TIMEOUT_MS = 180_000;
const LONG_OPERATION_BUDGET_MS = 200_000;
// A gateway blip fails within seconds; a failure later than this already spent a long budget.
const LONG_ROLE_RETRY_WINDOW_MS = 30_000;
// A short call may have a user waiting behind the web load balancer's 60 s idle timeout.
const SHORT_RATE_LIMIT_WINDOW_MS = 10_000;

export const SHORT_OPERATION_LIMITS: PublicAciOperationLimits = Object.freeze({
  requestTimeoutMs: SHORT_REQUEST_TIMEOUT_MS,
  operationBudgetMs: SHORT_OPERATION_BUDGET_MS,
  checkpointAgeMs: SHORT_OPERATION_BUDGET_MS + CHECKPOINT_HEADROOM_MS,
});

export const LONG_OPERATION_LIMITS: PublicAciOperationLimits = Object.freeze({
  requestTimeoutMs: LONG_REQUEST_TIMEOUT_MS,
  operationBudgetMs: LONG_OPERATION_BUDGET_MS,
  checkpointAgeMs: LONG_OPERATION_BUDGET_MS + CHECKPOINT_HEADROOM_MS,
});

/** Embeddings and interactive answers stay short; batch drafting, judging and critique get long-call room. */
export function publicAciOperationLimits(
  role: InferenceModelRole,
  profile: InferenceLatencyProfile,
): PublicAciOperationLimits {
  return isShortOperation(role, profile) ? SHORT_OPERATION_LIMITS : LONG_OPERATION_LIMITS;
}

/** How long after the first attempt began a transient failure may still be retried. */
export function transientRetryWindowMs(role: InferenceModelRole): number {
  return role === 'embed' ? Number.POSITIVE_INFINITY : LONG_ROLE_RETRY_WINDOW_MS;
}

/** The retry window for `role`, with a rate-limit wait held short wherever a short call runs. */
export function transientRetryWindows(
  role: InferenceModelRole,
  profile: InferenceLatencyProfile,
): TransientRetryWindows {
  const retryMs = transientRetryWindowMs(role);
  return {
    retryMs,
    rateLimitMs: isShortOperation(role, profile) ? SHORT_RATE_LIMIT_WINDOW_MS : retryMs,
  };
}

function isShortOperation(role: InferenceModelRole, profile: InferenceLatencyProfile): boolean {
  return role === 'embed' || profile === 'interactive';
}
