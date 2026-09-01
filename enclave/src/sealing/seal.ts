// KMS recipient attestation: response is encrypted to our ephemeral key — plaintext never leaves this heap.
import { KMSClient, DecryptCommand, EncryptCommand } from '@aws-sdk/client-kms';
import { generateKeyPairSync, privateDecrypt, constants } from 'crypto';
import { awsClientTransport } from '../aws/aws-transport.js';
import { getAttestationDoc } from './nsm.js';
import { assertDevKmsStubAllowed } from './dev-kms-stub-guard.js';

const REGION = process.env['AWS_REGION'] ?? 'us-east-1';
const MASTER_KEY_PURPOSE = 'master-key';
const MASTER_KEY_VERSION = '1';

// Shared tier binds tenantId into the KMS AAD so a master blob is cryptographically pinned to its
// tenant independent of which CMK opens it. Omitted for legacy dedicated blobs sealed
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
    ...awsClientTransport(),
  });
}

export async function sealMasterKey(
  masterKey: Buffer,
  kmsKeyId: string,
  tenantId?: string,
): Promise<Buffer> {
  return sealKmsPayload(masterKey, kmsKeyId, masterKeyContext(tenantId));
}

export async function sealKmsPayload(
  plaintext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  const response = await kmsClient().send(
    new EncryptCommand({
      KeyId: kmsKeyId,
      Plaintext: plaintext,
      EncryptionContext: encryptionContext,
    }),
  );
  if (!response.CiphertextBlob) throw new Error('recipient_kms_output_invalid');
  return Buffer.from(response.CiphertextBlob);
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
  return (await decryptWithContextAndKeyId(ciphertext, kmsKeyId, encryptionContext)).plaintext;
}

export async function decryptRecipientCiphertextWithKeyId(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<{ keyId: string; plaintext: Buffer }> {
  return decryptWithContextAndKeyId(ciphertext, kmsKeyId, encryptionContext);
}

async function decryptWithContextAndKeyId(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<{ keyId: string; plaintext: Buffer }> {
  // Dev-only: localstack KMS cannot perform the Nitro Recipient decrypt (it returns no
  // CiphertextForRecipient), so a plain KMS Decrypt stands in for every seal.ts decrypt (content
  // keyring, boot-manifest secrets, provider-refresh secrets, boot checkpoints, runtime-DB creds).
  // Fail-closed exactly like devMasterKeySealers: the shared guard throws outside development/test,
  // and the production EIF additionally pins NODE_ENV=production in entrypoint.sh AND denies this
  // flag from the parent env (aws-transport/egress-allowlist tests), so it can never activate there.
  // The AAD (EncryptionContext) is forwarded unchanged, so tenant/purpose binding is preserved.
  if (process.env['ENCLAVE_DEV_KMS_STUB'] === 'true') {
    assertDevKmsStubAllowed(process.env['NODE_ENV'] ?? '');
    const devResponse = await kmsClient().send(
      new DecryptCommand({
        KeyId: kmsKeyId,
        CiphertextBlob: ciphertext,
        EncryptionContext: encryptionContext,
      }),
    );
    if (!devResponse.KeyId || !devResponse.Plaintext) {
      throw new Error('recipient_kms_output_invalid');
    }
    return { keyId: devResponse.KeyId, plaintext: Buffer.from(devResponse.Plaintext) };
  }
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

  if (!response.KeyId || !response.CiphertextForRecipient)
    throw new Error('recipient_kms_output_invalid');
  return {
    keyId: response.KeyId,
    plaintext: privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(response.CiphertextForRecipient),
    ),
  };
}

export async function decryptRecipientCiphertext(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  return decryptWithContext(ciphertext, kmsKeyId, encryptionContext);
}
