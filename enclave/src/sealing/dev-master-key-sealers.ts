import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SealMasterKeyFn, UnsealMasterKeyFn } from '../tenant/TenantContextFactory.js';
import { assertDevKmsStubAllowed } from './dev-kms-stub-guard.js';

// Dev-only master-key seal/unseal: localstack KMS cannot do the Nitro Recipient decrypt, so a raw
// DATA_KEK stands in for the per-tenant CMK. Refuses to load outside development/test — the
// production EIF must never have a master-key path outside PCR-gated KMS custody.
export function devMasterKeySealers(
  nodeEnv: string,
  dataKek: string | undefined,
): { sealMasterKey: SealMasterKeyFn; unsealMasterKey: UnsealMasterKeyFn } {
  assertDevKmsStubAllowed(nodeEnv);
  const key = Buffer.from(dataKek ?? '', 'base64');
  if (key.length !== 32) {
    throw new Error('ENCLAVE_DEV_KMS_STUB requires a 32-byte base64 DATA_KEK');
  }
  // Version marker in the AAD so a format change can never be silently accepted across builds.
  const aad = (tenantId: string): Buffer => Buffer.from(`dev-master-key:v1:${tenantId}`);
  const sealMasterKey: SealMasterKeyFn = async (masterKey, _kmsKeyId, tenantId) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad(tenantId));
    const ciphertext = Buffer.concat([cipher.update(masterKey), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
  };
  const unsealMasterKey: UnsealMasterKeyFn = async (blob, _kmsKeyId, tenantId) => {
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    decipher.setAAD(aad(tenantId));
    decipher.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
  };
  return { sealMasterKey, unsealMasterKey };
}
