import type { GenerationContextV1 } from '@folklore/contracts';
import type { InferenceUsageSink, VerifiedActivePolicySnapshotV1 } from '@folklore/inference';
import type { VerifiedBootManifest } from '../attestation/BootManifestVerifier.js';
import type { RuntimeEvidenceSessionPort } from '../attestation/ports.js';
import type { BootBoundGenerationContext } from '../inference/BootStateActivePolicyReferenceVerifier.js';
import { ANSWER_CACHE_VERSION, type InferenceModel } from '../inference/CachedInference.js';
import { expectedTenantGenerationContext } from '../inference/expected-tenant-generation-context.js';
import { SharedPoolRuntimeEvidence } from '../inference/SharedPoolRuntimeEvidence.js';
import type { UpstreamCallGate } from '../inference/TenantPolicyBoundInference.js';
import type { LlmOperationCache } from '../inference/vector-cache.js';
import {
  dedicatedCachedInference,
  poolPolicyBoundInference,
  type PoolPolicyPorts,
} from '../inference/tenant-inference-builders.js';
import type { TenantContext } from './tenant-context.js';
import type { TenantGenerationRegistry } from './TenantGenerationRegistry.js';
import type { TenantPolicySnapshotRegistry } from './TenantPolicySnapshotRegistry.js';

export interface TenantPolicyWiringDeps<S extends VerifiedActivePolicySnapshotV1> {
  readonly sharedPool: boolean;
  readonly generations: TenantGenerationRegistry<TenantContext, S>;
  readonly snapshots: TenantPolicySnapshotRegistry<S, TenantContext>;
  readonly attestation: () => RuntimeEvidenceSessionPort | null | undefined;
  readonly bootManifest: () =>
    | Pick<VerifiedBootManifest, 'providerInferenceTrustPolicy'>
    | undefined;
  readonly bootContext: () => BootBoundGenerationContext | undefined;
  readonly onPolicyRefusal?: (code: string | undefined) => void;
}

export type AnswerInferenceBuild = (
  orgId: string,
  tenant: Pick<TenantContext, 'activePolicySnapshot'>,
  cache: LlmOperationCache,
) => InferenceModel;

/** Binds each tenant's installed policy snapshot to the enclave's boot state and its inference paths. */
export class TenantPolicyWiring<S extends VerifiedActivePolicySnapshotV1> {
  constructor(private readonly deps: TenantPolicyWiringDeps<S>) {}

  snapshotFor(tenantId: string): S | undefined {
    return this.deps.snapshots.get(tenantId);
  }

  evictFor(tenantId: string): (failed?: VerifiedActivePolicySnapshotV1, code?: string) => void {
    return (failed, code) => {
      if (failed && this.deps.snapshots.evict(tenantId, failed)) this.deps.onPolicyRefusal?.(code);
    };
  }

  refusalEpochFor(tenantId: string): () => number {
    return () => this.deps.snapshots.refusalEpoch(tenantId);
  }

  confirmFor(tenantId: string): (verified: VerifiedActivePolicySnapshotV1, epoch: number) => void {
    return (verified, epoch) => this.deps.snapshots.confirm(tenantId, verified, epoch);
  }

  expectedContextFor(tenantId: string, snapshot: S): GenerationContextV1 {
    return expectedTenantGenerationContext({
      tenantId,
      snapshot,
      tenant: this.deps.generations.get(tenantId)?.context,
      boot: this.deps.bootContext(),
    });
  }

  runtimeEvidenceFor(tenantId: string): SharedPoolRuntimeEvidence {
    return new SharedPoolRuntimeEvidence({
      tenantId,
      installedSnapshot: () => this.snapshotFor(tenantId),
      providerPolicyInstalled: () => this.providerPolicyInstalled(),
      attestation: this.deps.attestation,
      assignedTenant: () => this.deps.generations.get(tenantId)?.context,
      bootContext: this.deps.bootContext,
    });
  }

  answerInferenceBuilder(
    policy: PoolPolicyPorts,
    usageSink: InferenceUsageSink,
    upstreamGate?: UpstreamCallGate,
  ): AnswerInferenceBuild {
    return (orgId, tenant, cache) =>
      this.deps.sharedPool
        ? poolPolicyBoundInference({
            orgId,
            snapshot: () => tenant.activePolicySnapshot(),
            policy,
            operationCache: cache,
            usageSink,
            latencyProfile: 'interactive',
            ...(upstreamGate === undefined ? {} : { upstreamGate }),
          })
        : dedicatedCachedInference(cache, ANSWER_CACHE_VERSION);
  }

  private providerPolicyInstalled(): boolean {
    return this.deps.bootManifest()?.providerInferenceTrustPolicy !== undefined;
  }
}
