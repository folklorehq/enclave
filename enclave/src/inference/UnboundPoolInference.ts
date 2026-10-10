import type { SynthesisInference } from './CachedInference.js';
import { TenantPolicyBoundInferenceError } from './TenantPolicyBoundInference.js';

export const POOL_BACKEND_UNBOUND = 'runtime_evidence_pool_backend_unbound';

/** A pool tenant's fallback backend: it refuses every operation, so no pool path reaches the global one. */
export class UnboundPoolInference implements SynthesisInference {
  async embed(): Promise<number[]> {
    throw this.refusal();
  }

  async generate(): Promise<string> {
    throw this.refusal();
  }

  async critique(): Promise<string> {
    throw this.refusal();
  }

  private refusal(): TenantPolicyBoundInferenceError {
    return new TenantPolicyBoundInferenceError(
      'active_policy_snapshot_refresh_failed',
      POOL_BACKEND_UNBOUND,
    );
  }
}
