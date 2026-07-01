// KMS recipient attestation: response is encrypted to our ephemeral key — plaintext never leaves this heap.
import { KMSClient, DecryptCommand, EncryptCommand } from '@aws-sdk/client-kms';
import { generateKeyPairSync, privateDecrypt, constants } from 'crypto';
import { getAttestationDoc } from './nsm.js';

const PROXY_PORT = process.env['VSOCK_KMS_PROXY_PORT'] ?? '8000';
const REGION = process.env['AWS_REGION'] ?? 'us-east-1';
const ENCRYPTION_CONTEXT = { purpose: 'master-key', version: '1' };

function kmsClient(): KMSClient {
  return new KMSClient({
    region: REGION,
    endpoint: `https://localhost:${PROXY_PORT}`,
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
  // ephemeral key embedded in attDoc so KMS encrypts the response to us, not over the wire
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
