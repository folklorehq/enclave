/** Decrypts an ingest-Lambda webhook payload via ECIES (X25519 + HKDF-SHA256 + AES-256-GCM); must match ingest-proxy/src/lambdas/handler.ts exactly. */
import { diffieHellman, hkdfSync, createDecipheriv, createPublicKey, KeyObject } from 'crypto';

export interface EncryptedPayload {
  ephemeralPublicKey: string; // hex
  nonce: string; // hex, 12 bytes
  ciphertext: string; // hex, includes 16-byte GCM auth tag appended
}

const X25519_RAW_KEY_BYTES = 32;
const AES_KEY_BYTES = 32;
const GCM_TAG_BYTES = 16;

function deriveAesKey(
  sharedSecret: Buffer,
  ephemeralPubBytes: Buffer,
  recipientPubBytes: Buffer,
): Buffer {
  const info = Buffer.concat([
    Buffer.from('folklore-ingest-v1:'),
    ephemeralPubBytes,
    recipientPubBytes,
  ]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), info, AES_KEY_BYTES));
}

export function decryptPayload(msg: EncryptedPayload, privateKey: KeyObject): Buffer {
  const ephemeralPubBytes = Buffer.from(msg.ephemeralPublicKey, 'hex');
  const nonce = Buffer.from(msg.nonce, 'hex');
  const ciphertextWithTag = Buffer.from(msg.ciphertext, 'hex');

  const ephemeralPub = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: ephemeralPubBytes.toString('base64url') },
    format: 'jwk',
  });

  const sharedSecret = diffieHellman({ privateKey, publicKey: ephemeralPub });

  const recipientPubBytes = Buffer.from(
    createPublicKey(privateKey)
      .export({ type: 'spki', format: 'der' })
      .slice(-X25519_RAW_KEY_BYTES),
  );

  const aesKey = deriveAesKey(sharedSecret, ephemeralPubBytes, recipientPubBytes);

  // Python's AESGCM appends the 16-byte auth tag to the ciphertext
  const authTag = ciphertextWithTag.slice(-GCM_TAG_BYTES);
  const ciphertext = ciphertextWithTag.slice(0, -GCM_TAG_BYTES);

  const decipher = createDecipheriv('aes-256-gcm', aesKey, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
