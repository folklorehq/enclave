import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { MintMasterKeyFn, UnsealMasterKeyFn } from '../tenant/TenantContextFactory.js';
import { assertDevKmsStubAllowed } from './dev-kms-stub-guard.js';

const MASTER_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;

// Dev-only master-key mint/unseal: localstack KMS cannot do the Nitro Recipient calls, so a raw
// DATA_KEK stands in for the per-tenant CMK. Refuses to load outside development/test — the
// production EIF must never have a master-key path outside PCR-gated KMS custody.
export function devMasterKeySealers(
  nodeEnv: string,
  dataKek: string | undefined,
): { mintMasterKey: MintMasterKeyFn; unsealMasterKey: UnsealMasterKeyFn } {
  assertDevKmsStubAllowed(nodeEnv);
  const key = Buffer.from(dataKek ?? '', 'base64');
  if (key.length !== MASTER_KEY_BYTES) {
    throw new Error('ENCLAVE_DEV_KMS_STUB requires a 32-byte base64 DATA_KEK');
  }
  // Version marker in the AAD so a format change can never be silently accepted across builds.
  const aad = (tenantId: string): Buffer => Buffer.from(`dev-master-key:v1:${tenantId}`);
  const mintMasterKey: MintMasterKeyFn = async (_kmsKeyId, tenantId) => {
    const masterKey = randomBytes(MASTER_KEY_BYTES);
    const iv = randomBytes(GCM_IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad(tenantId));
    const ciphertext = Buffer.concat([cipher.update(masterKey), cipher.final()]);
    return { masterKey, sealedBlob: Buffer.concat([iv, cipher.getAuthTag(), ciphertext]) };
  };
  const unsealMasterKey: UnsealMasterKeyFn = async (blob, _kmsKeyId, tenantId) => {
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, GCM_IV_BYTES));
    decipher.setAAD(aad(tenantId));
    decipher.setAuthTag(blob.subarray(GCM_IV_BYTES, GCM_IV_BYTES + GCM_TAG_BYTES));
    return Buffer.concat([
      decipher.update(blob.subarray(GCM_IV_BYTES + GCM_TAG_BYTES)),
      decipher.final(),
    ]);
  };
  return { mintMasterKey, unsealMasterKey };
}
