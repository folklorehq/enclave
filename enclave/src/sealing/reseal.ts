import { type S3Client } from '@aws-sdk/client-s3';
import { sealMasterKey, unsealMasterKey } from './seal.js';
import { readSealedBlob, writeSealedBlob } from './sealed-blob-store.js';

// Seam so a reseal is testable without live KMS/NSM; defaults bind to seal.ts's attestation-gated calls (ADL #30).
export type UnsealFn = (blob: Buffer, kmsKeyId: string, tenantId: string) => Promise<Buffer>;
export type SealFn = (masterKey: Buffer, kmsKeyId: string, tenantId: string) => Promise<Buffer>;

export interface ResealDeps {
  s3: S3Client;
  sealedBlobBucket: string;
  unseal?: UnsealFn;
  seal?: SealFn;
}

export interface ResealRequest {
  tenantId: string;
  sourceKmsKeyId: string;
  targetKmsKeyId: string;
}

// ADL #61: the tenantId AAD is preserved, so key identity is unchanged — only the KMS principal that may unseal changes.
export async function resealMasterKey(deps: ResealDeps, req: ResealRequest): Promise<void> {
  const unseal = deps.unseal ?? unsealMasterKey;
  const seal = deps.seal ?? sealMasterKey;

  const blob = await readSealedBlob(deps.s3, deps.sealedBlobBucket, req.tenantId);
  if (!blob) throw new Error(`reseal: no sealed master blob for tenant ${req.tenantId}`);

  const masterKey = await unseal(blob, req.sourceKmsKeyId, req.tenantId);
  const resealed = await seal(masterKey, req.targetKmsKeyId, req.tenantId);
  await writeSealedBlob(deps.s3, deps.sealedBlobBucket, req.tenantId, resealed);
}
