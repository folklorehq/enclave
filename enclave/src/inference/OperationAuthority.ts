import type { InferenceModelRole } from '@folklore/contracts';
import type {
  AciTrustContext,
  TrustedTimeAuthorityPort,
  TrustedTimeReadContext,
  TrustedTimeSample,
  VerifiedActivePolicyRoleBindingV1,
  VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import {
  assertVerifiedActivePolicyRoleBindingV1,
  assertVerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import { PublicAciPinnedKeysetAuthority } from './PublicAciPinnedKeysetAuthority.js';
import type { TenantPolicyFreshnessPort } from './TenantPolicyBoundInference.js';
import { installedSnapshotHighWater } from './renewal-grace.js';
import {
  publicAciOperationLimits,
  type InferenceLatencyProfile,
} from './public-aci-operation-limits.js';

export type PolicyRole = VerifiedActivePolicySnapshotV1['policy']['roles'][InferenceModelRole];

export interface OperationAdmission {
  readonly role: PolicyRole;
  readonly trustedTimeContext: AciTrustContext;
  readonly authority: PublicAciPinnedKeysetAuthority;
  readonly trustedTime: TrustedTimeAuthorityPort;
  readonly remainingBudget: () => number;
}

export interface OperationAuthorityOptions {
  readonly tenantId: string;
  readonly freshness: TenantPolicyFreshnessPort;
  readonly bootEpoch: string;
  readonly latencyProfile?: InferenceLatencyProfile;
  readonly providerPolicyGeneration: number;
}

export interface OperationAdmitHooks {
  readonly afterRoleCheck?: (snapshot: VerifiedActivePolicySnapshotV1) => void;
}

function exactRole(
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
): PolicyRole {
  const role = snapshot.policy.roles[binding.role];
  if (
    snapshot.tenantId !== binding.orgId ||
    binding.orgId !== snapshot.orgId ||
    binding.deploymentId !== snapshot.deploymentId ||
    snapshot.roleBindingFor(binding.role) !== binding ||
    role.model !== binding.modelId ||
    role.modelRevision !== binding.modelRevision
  )
    throw new Error('public_aci_role_binding_mismatch');
  return role;
}

function millisecondsTrustedTime(
  source: TrustedTimeAuthorityPort,
  context: AciTrustContext,
  role: { establishedAt: number; expiresAt: number },
  snapshot: VerifiedActivePolicySnapshotV1,
): TrustedTimeAuthorityPort {
  return {
    read: async (requested: TrustedTimeReadContext = {}): Promise<TrustedTimeSample> => {
      const sample = await source.read({
        orgId: context.orgId,
        deploymentId: context.deploymentId,
      });
      const ms = sample.trustedNow;
      if (
        !Number.isSafeInteger(ms) ||
        ms <= 0 ||
        sample.orgId !== context.orgId ||
        sample.deploymentId !== context.deploymentId ||
        sample.bootEpoch !== context.bootEpoch ||
        sample.checkpointDigest !== context.checkpointDigest ||
        ms < role.establishedAt ||
        ms >= role.expiresAt ||
        ms >= snapshot.policy.lifetime.snapshotExpiresAt ||
        (requested.orgId !== undefined && requested.orgId !== sample.orgId) ||
        (requested.deploymentId !== undefined && requested.deploymentId !== sample.deploymentId) ||
        (requested.bootEpoch !== undefined && requested.bootEpoch !== sample.bootEpoch) ||
        (requested.checkpointDigest !== undefined &&
          requested.checkpointDigest !== sample.checkpointDigest)
      )
        throw new Error('public_aci_operation_time_invalid');
      return { ...sample, trustedNow: Math.floor(ms / 1000) };
    },
  };
}

/** The one admission every provider route passes: tenant match, trusted time, pinned authority and the operation budget. */
export class OperationAuthority {
  constructor(private readonly options: OperationAuthorityOptions) {}

  async admit(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    hooks: OperationAdmitHooks = {},
  ): Promise<OperationAdmission> {
    const { options } = this;
    assertVerifiedActivePolicySnapshotV1(snapshot);
    assertVerifiedActivePolicyRoleBindingV1(binding);
    if (
      snapshot.orgId !== options.tenantId ||
      snapshot.tenantId !== options.tenantId ||
      binding.orgId !== options.tenantId
    )
      throw new Error('public_aci_tenant_mismatch');
    const role = exactRole(binding, snapshot);
    hooks.afterRoleCheck?.(snapshot);
    const limits = publicAciOperationLimits(binding.role, options.latencyProfile ?? 'batch');
    const startedAt = performance.now();
    const remainingBudget = () => {
      const remaining = Math.floor(limits.operationBudgetMs - (performance.now() - startedAt));
      if (remaining <= 0) throw new Error('public_aci_operation_deadline');
      return remaining;
    };
    const sample = await options.freshness.trustedTime.read({
      orgId: snapshot.orgId,
      deploymentId: snapshot.deploymentId,
    });
    if (
      sample.orgId !== snapshot.orgId ||
      sample.deploymentId !== snapshot.deploymentId ||
      sample.bootEpoch !== options.bootEpoch
    )
      throw new Error('public_aci_trusted_time_context_mismatch');
    const expectedContext = options.freshness.expectedContext();
    const trustedTimeContext: AciTrustContext = {
      orgId: sample.orgId,
      deploymentId: sample.deploymentId,
      bootEpoch: sample.bootEpoch,
      checkpointDigest: sample.checkpointDigest,
    };
    const authority = new PublicAciPinnedKeysetAuthority({
      snapshot,
      expectedContext,
      // Per-operation pin uses the same bounded renewal grace as the freshness refresh.
      durable: installedSnapshotHighWater(options.freshness.highWater, snapshot.durableCheckpoint),
      trustedTimeContext,
      providerPolicyGeneration: options.providerPolicyGeneration,
    });
    remainingBudget();
    const trustedTime = millisecondsTrustedTime(
      options.freshness.trustedTime,
      trustedTimeContext,
      role,
      snapshot,
    );
    return { role, trustedTimeContext, authority, trustedTime, remainingBudget };
  }
}
