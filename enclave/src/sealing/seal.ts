/**
 * Master key sealing — Model 2: KMS with PCR attestation condition.
 *
 * Seal   (kms:Encrypt)  — any caller with the enclave IAM role.
 *                         No PCR required; encrypting doesn't expose plaintext.
 * Unseal (kms:Decrypt)  — requires a valid Nitro attestation doc whose PCR0
 *                         matches the key policy. A code change shifts PCR0,
 *                         the condition fails, and the enclave refuses to start.
 *
 * KMS never returns decrypted plaintext over the wire. Instead it encrypts the
 * response to the ephemeral RSA public key we embed in the attestation doc —
 * plaintext only exists in this process's heap.
 */
import { KMSClient, DecryptCommand, EncryptCommand } from '@aws-sdk/client-kms';
import { generateKeyPairSync, privateDecrypt, constants } from 'crypto';
import { getAttestationDoc } from './nsm.js';

const PROXY_PORT = process.env['VSOCK_KMS_PROXY_PORT'] ?? '8000';
const REGION = process.env['AWS_REGION'] ?? 'us-east-1';
const ENCRYPTION_CONTEXT = { purpose: 'master-key', version: '1' };

function kmsClient(): KMSClient {
  return new KMSClient({
    region: REGION,
    // All AWS calls route through the vsock proxy on the parent instance.
    // TLS terminates here — the proxy forwards raw bytes without parsing them.
    endpoint: `http://localhost:${PROXY_PORT}`,
  });
}

export async function sealMasterKey(masterKey: Buffer, kmsKeyId: string): Promise<Buffer> {
  const response = await kmsClient().send(
    new EncryptCommand({
      KeyId: kmsKeyId,
      Plaintext: masterKey,
      EncryptionContext: ENCRYPTION_CONTEXT,
    }),
  );
  return Buffer.from(response.CiphertextBlob!);
}

export async function unsealMasterKey(ciphertext: Buffer, kmsKeyId: string): Promise<Buffer> {
  // One-time ephemeral RSA-2048 key — embedded in the attestation doc so KMS
  // encrypts its response to us rather than returning raw plaintext.
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ephemeralPubDer = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }));

  const attDoc = getAttestationDoc(ephemeralPubDer);

  const response = await kmsClient().send(
    new DecryptCommand({
      KeyId: kmsKeyId,
      CiphertextBlob: ciphertext,
      EncryptionContext: ENCRYPTION_CONTEXT,
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
