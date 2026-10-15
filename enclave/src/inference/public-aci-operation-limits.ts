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
// The full 8192-token role cap, reasoning included, decodes in ~273 s at a sustained 30 tokens/s.
const LONG_REQUEST_TIMEOUT_MS = 300_000;
const LONG_OPERATION_BUDGET_MS = 320_000;
// An uncapped batch draft gets the same 8192 tokens at a sustained ~17 tokens/s.
const DRAFT_REQUEST_TIMEOUT_MS = 480_000;
const DRAFT_OPERATION_BUDGET_MS = 500_000;
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

export const DRAFT_OPERATION_LIMITS: PublicAciOperationLimits = Object.freeze({
  requestTimeoutMs: DRAFT_REQUEST_TIMEOUT_MS,
  operationBudgetMs: DRAFT_OPERATION_BUDGET_MS,
  checkpointAgeMs: DRAFT_OPERATION_BUDGET_MS + CHECKPOINT_HEADROOM_MS,
});

export const LONGEST_CHECKPOINT_AGE_MS = DRAFT_OPERATION_LIMITS.checkpointAgeMs;

/** Embeddings and interactive answers stay short; batch drafting gets the most room, judging and critique long-call room. */
export function publicAciOperationLimits(
  role: InferenceModelRole,
  profile: InferenceLatencyProfile,
): PublicAciOperationLimits {
  if (isShortOperation(role, profile)) return SHORT_OPERATION_LIMITS;
  return role === 'generate' ? DRAFT_OPERATION_LIMITS : LONG_OPERATION_LIMITS;
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
