import type { Cache } from '@folklore/core';
import type { GenerationContextV1 } from '@folklore/contracts';
import type { InferenceUsageSink, VerifiedActivePolicySnapshotV1 } from '@folklore/inference';
import type { VerifiedBootManifest } from '../attestation/BootManifestVerifier.js';
import type { RuntimeEvidenceSessionPort } from '../attestation/ports.js';
import type { BootBoundGenerationContext } from '../inference/BootStateActivePolicyReferenceVerifier.js';
import { ANSWER_CACHE_VERSION, type InferenceModel } from '../inference/CachedInference.js';
import { expectedTenantGenerationContext } from '../inference/expected-tenant-generation-context.js';
import { SharedPoolRuntimeEvidence } from '../inference/SharedPoolRuntimeEvidence.js';
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
}

export type AnswerInferenceBuild = (
  orgId: string,
  tenant: Pick<TenantContext, 'activePolicySnapshot'>,
  cache: Cache,
) => InferenceModel;

/** Binds each tenant's installed policy snapshot to the enclave's boot state and its inference paths. */
export class TenantPolicyWiring<S extends VerifiedActivePolicySnapshotV1> {
  constructor(private readonly deps: TenantPolicyWiringDeps<S>) {}

  snapshotFor(tenantId: string): S | undefined {
    return this.deps.snapshots.get(tenantId);
  }

  evictFor(tenantId: string): (failed?: VerifiedActivePolicySnapshotV1) => void {
    return (failed) => {
      if (failed) this.deps.snapshots.evict(tenantId, failed);
    };
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
  ): AnswerInferenceBuild {
    return (orgId, tenant, cache) =>
      this.deps.sharedPool
        ? poolPolicyBoundInference({
            orgId,
            snapshot: () => tenant.activePolicySnapshot(),
            policy,
            operationCache: cache,
            usageSink,
          })
        : dedicatedCachedInference(cache, ANSWER_CACHE_VERSION);
  }

  private providerPolicyInstalled(): boolean {
    return this.deps.bootManifest()?.providerInferenceTrustPolicy !== undefined;
  }
}
