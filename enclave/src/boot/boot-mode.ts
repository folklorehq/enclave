export const POOL_ID_REQUIRED = 'pool_id_required';
export const SHARED_POOL_BOOT_MANIFEST_UNVERIFIED = 'shared_pool_boot_manifest_unverified';
export const SHARED_POOL_IDENTITY_MISMATCH = 'shared_pool_identity_mismatch';

const PRODUCTION = 'production';

/** The enclave is a shared pool in every mode; a boot without a pool id is refused. */
export function assertPoolId(poolId: string): void {
  if (poolId.length === 0) throw new Error(POOL_ID_REQUIRED);
}

export function assertSharedPoolIdentity(input: {
  readonly nodeEnv: string | undefined;
  readonly poolId: string;
  readonly verifiedOrgId: string | undefined;
  readonly verifiedDeploymentId: string | undefined;
}): void {
  if (input.nodeEnv !== PRODUCTION) return;
  if (input.verifiedOrgId === undefined && input.verifiedDeploymentId === undefined) {
    throw new Error(SHARED_POOL_BOOT_MANIFEST_UNVERIFIED);
  }
  if (input.verifiedOrgId !== input.poolId || input.verifiedDeploymentId !== input.poolId) {
    throw new Error(SHARED_POOL_IDENTITY_MISMATCH);
  }
}
