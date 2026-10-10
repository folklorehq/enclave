import type { GenerationContextV1 } from '@folklore/contracts';
import type { VerifiedActivePolicySnapshotV1 } from '@folklore/inference';
import type { BootBoundGenerationContext } from './BootStateActivePolicyReferenceVerifier.js';

export interface AssignedTenantDeployment {
  readonly tenantId: string;
  readonly deploymentId: string;
  readonly tenantDeploymentId?: string;
}

/** The generation context a tenant's installed snapshot must carry on this verified boot. */
export function expectedTenantGenerationContext(input: {
  readonly tenantId: string;
  readonly snapshot: VerifiedActivePolicySnapshotV1;
  readonly tenant: AssignedTenantDeployment | undefined;
  readonly boot: BootBoundGenerationContext | undefined;
}): GenerationContextV1 {
  const { tenantId, snapshot, tenant, boot } = input;
  if (!tenant || !boot) throw new Error('active_policy_freshness_context_unavailable');
  const deploymentId = tenant.tenantDeploymentId ?? tenant.deploymentId;
  if (!deploymentId || tenant.tenantId !== tenantId) {
    throw new Error('active_policy_freshness_context_mismatch');
  }
  return {
    orgId: tenantId,
    deploymentId,
    policyDigest: snapshot.policyDigest,
    policyGeneration: snapshot.policyGeneration,
    activationGeneration: snapshot.activationGeneration,
    configurationGeneration: snapshot.configurationGeneration,
    keysetEpoch: snapshot.policy.minimumHighWater.keysetEpoch,
    keysetDigest: snapshot.policy.minimumHighWater.keysetDigest,
    releaseId: boot.releaseId,
    protectedSourceCommit: boot.protectedSourceCommit,
    eifDigest: boot.eifDigest,
    pcr0: boot.pcr0,
    bootRootDigest: boot.bootRootDigest,
  };
}
