/**
 * Master key and derived key generation via HKDF-SHA256.
 *
 * Every per-purpose key is derived deterministically from the master key.
 * A single sealed blob is all that needs to persist across reboots.
 */
import { hkdfSync, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { getEntropy } from './nsm.js';

export function generateMasterKey(): Buffer {
  return getEntropy(32);
}

export function deriveKey(masterKey: Buffer, purpose: string, length = 32): Buffer {
  return Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), purpose, length));
}

export interface IngestKeypair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyRaw: Buffer;
}

/**
 * Stable X25519 keypair for webhook ingest decryption.
 * Deterministic — same master key produces the same keypair on every boot,
 * so the public key stored in Postgres stays valid across reboots and upgrades.
 */
export function deriveIngestKeypair(masterKey: Buffer): IngestKeypair {
  const seed = deriveKey(masterKey, 'ingest-keypair-v1', 32);

  const privateKey = createPrivateKey({
    key: { kty: 'OKP', crv: 'X25519', d: seed.toString('base64url') },
    format: 'jwk',
  });
  const publicKey = createPublicKey(privateKey);

  // Raw 32-byte public key — safe to store in Postgres
  const publicKeyRaw = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).slice(-32));

  return { privateKey, publicKey, publicKeyRaw };
}
