export const DEDICATED_MODE_RETIRED = 'dedicated_mode_retired';
export const SHARED_POOL_BOOT_MANIFEST_UNVERIFIED = 'shared_pool_boot_manifest_unverified';
export const SHARED_POOL_IDENTITY_MISMATCH = 'shared_pool_identity_mismatch';

const PRODUCTION = 'production';

export function assertDedicatedModeRetired(input: {
  readonly nodeEnv: string | undefined;
  readonly poolId: string;
}): void {
  if (input.nodeEnv === PRODUCTION && input.poolId.length === 0) {
    throw new Error(DEDICATED_MODE_RETIRED);
  }
}

export function assertSharedPoolIdentity(input: {
  readonly nodeEnv: string | undefined;
  readonly poolId: string;
  readonly verifiedOrgId: string | undefined;
  readonly verifiedDeploymentId: string | undefined;
}): void {
  if (input.nodeEnv !== PRODUCTION || input.poolId.length === 0) return;
  if (input.verifiedOrgId === undefined && input.verifiedDeploymentId === undefined) {
    throw new Error(SHARED_POOL_BOOT_MANIFEST_UNVERIFIED);
  }
  if (input.verifiedOrgId !== input.poolId || input.verifiedDeploymentId !== input.poolId) {
    throw new Error(SHARED_POOL_IDENTITY_MISMATCH);
  }
}
