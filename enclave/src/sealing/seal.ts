// KMS recipient attestation: response is encrypted to our ephemeral key — plaintext never leaves this heap.
import { KMSClient, DecryptCommand, EncryptCommand } from '@aws-sdk/client-kms';
import { generateKeyPairSync, privateDecrypt, constants } from 'crypto';
import { getAttestationDoc } from './nsm.js';

const PROXY_PORT = process.env['VSOCK_KMS_PROXY_PORT'] ?? '8000';
const REGION = process.env['AWS_REGION'] ?? 'us-east-1';
const MASTER_KEY_PURPOSE = 'master-key';
const MASTER_KEY_VERSION = '1';

// Shared tier binds tenantId into the KMS AAD so a master blob is cryptographically pinned to its
// tenant independent of which CMK opens it (ADL #30). Omitted for legacy dedicated blobs sealed
// before binding — unseal below falls back to the tenant-agnostic context for those.
function masterKeyContext(tenantId?: string): Record<string, string> {
  const context: Record<string, string> = {
    purpose: MASTER_KEY_PURPOSE,
    version: MASTER_KEY_VERSION,
  };
  if (tenantId) context['tenantId'] = tenantId;
  return context;
}

function kmsClient(): KMSClient {
  return new KMSClient({
    region: REGION,
    endpoint: `https://localhost:${PROXY_PORT}`,
  });
}

export async function sealMasterKey(
  masterKey: Buffer,
  kmsKeyId: string,
  tenantId?: string,
): Promise<Buffer> {
  const response = await kmsClient().send(
    new EncryptCommand({
      KeyId: kmsKeyId,
      Plaintext: masterKey,
      EncryptionContext: masterKeyContext(tenantId),
    }),
  );
  return Buffer.from(response.CiphertextBlob!);
}

// KMS raises this only when the ciphertext/AAD don't match — i.e. a blob sealed before
// tenant-binding. Transient KMS/attestation failures raise other names and must surface.
const CIPHERTEXT_MISMATCH = 'InvalidCiphertextException';

export async function unsealMasterKey(
  ciphertext: Buffer,
  kmsKeyId: string,
  tenantId?: string,
): Promise<Buffer> {
  try {
    return await decryptWithContext(ciphertext, kmsKeyId, masterKeyContext(tenantId));
  } catch (err) {
    // Retry the tenant-agnostic AAD only on a ciphertext mismatch, so a transient failure isn't
    // masked by a second failing decrypt. The per-tenant PCR0-gated CMK stays the real gate.
    if (!tenantId || !(err instanceof Error) || err.name !== CIPHERTEXT_MISMATCH) throw err;
    console.warn('legacy-aad-unseal', { tenant: tenantId });
    return decryptWithContext(ciphertext, kmsKeyId, masterKeyContext());
  }
}

async function decryptWithContext(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  // ephemeral key embedded in attDoc so KMS encrypts the response to us, not over the wire
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ephemeralPubDer = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }));

  const attDoc = getAttestationDoc(ephemeralPubDer);

  const response = await kmsClient().send(
    new DecryptCommand({
      KeyId: kmsKeyId,
      CiphertextBlob: ciphertext,
      EncryptionContext: encryptionContext,
      Recipient: {
        KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256',
        AttestationDocument: attDoc,
      },
    }),
  );

  return privateDecrypt(
    { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(response.CiphertextForRecipient!),
  );
}
