import {
  recoveryKeyBindingIdentityV1,
  type RecoveryKeyBindingIdentityV1,
  type RecoveryKeyBindingV1,
} from '@folklore/contracts';
import type { TenantPolicyAssignment } from '../tenant/TenantAssignmentApplier.js';

export type RecoveryBoundAssignment = Pick<
  TenantPolicyAssignment,
  'tenantId' | 'deploymentId' | 'tenantDeploymentId' | 'recoveryPubkey' | 'recoveryKeyBinding'
>;

// The key counts as signed only when the signed tenant id is itself a commitment to that key.
export function signedRecoveryKeyFor(assignment: RecoveryBoundAssignment): string | undefined {
  const binding = assignment.recoveryKeyBinding;
  if (!binding) return undefined;
  if (!assignment.recoveryPubkey) throw new Error('tenant_recovery_binding_key_missing');
  const identity = derivedIdentity(binding, assignment.recoveryPubkey);
  if (identity.orgId !== assignment.tenantId) {
    throw new Error('tenant_recovery_binding_org_mismatch');
  }
  if (binding.basis === 'placement_enrollment' && !deploymentMatches(identity, assignment)) {
    throw new Error('tenant_recovery_binding_deployment_mismatch');
  }
  return assignment.recoveryPubkey.toLowerCase();
}

function derivedIdentity(
  binding: RecoveryKeyBindingV1,
  recoveryPublicKeyHex: string,
): RecoveryKeyBindingIdentityV1 {
  try {
    return recoveryKeyBindingIdentityV1({ binding, recoveryPublicKeyHex });
  } catch {
    throw new Error('tenant_recovery_binding_invalid');
  }
}

function deploymentMatches(
  identity: RecoveryKeyBindingIdentityV1,
  assignment: RecoveryBoundAssignment,
): boolean {
  if (identity.deploymentId !== assignment.deploymentId) return false;
  return (
    assignment.tenantDeploymentId === undefined ||
    assignment.tenantDeploymentId === identity.deploymentId
  );
}
