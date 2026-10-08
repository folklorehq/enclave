export class MasterKeyResealSeamError extends Error {
  constructor(detail: string) {
    super(`master key reseal not yet integrated: ${detail}`);
    this.name = 'MasterKeyResealSeamError';
  }
}

export interface ResealRequest {
  tenantId: string;
  sourceKmsKeyId: string;
  targetKmsKeyId: string;
}

// The master CMK denies Encrypt and only an attested mint seals a master blob, so nothing can reseal one.
export async function resealMasterKey(_request: ResealRequest): Promise<never> {
  throw new MasterKeyResealSeamError(
    'a master blob is sealed only by an attested mint, so no reseal path exists',
  );
}
