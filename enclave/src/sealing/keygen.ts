import { hkdfSync, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { entropyToMnemonic } from 'bip39';

const LLM_CACHE_NAME_KEY_PURPOSE = 'llm-cache-name-v1';

export function deriveKey(masterKey: Buffer, purpose: string, length = 32): Buffer {
  return Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), purpose, length));
}

// Keys the cache object names so a host that can list the bucket cannot test guesses against them.
export function deriveLlmCacheNameKey(masterKey: Buffer): Buffer {
  return deriveKey(masterKey, LLM_CACHE_NAME_KEY_PURPOSE);
}

// BIP39 24-word recovery phrase; sealed to the customer's key at first boot, never held by Folklore.
export function deriveMnemonic(masterKey: Buffer): string {
  // BIP39 requires exactly 256 bits (32 bytes) of entropy for a 24-word mnemonic.
  return entropyToMnemonic(masterKey.toString('hex'));
}

export interface IngestKeypair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyRaw: Buffer;
}

// Deterministic across reboots — public key written to SSM stays valid after upgrades.
export function deriveIngestKeypair(masterKey: Buffer): IngestKeypair {
  const seed = deriveKey(masterKey, 'ingest-keypair-v1', 32);

  // X25519 JWK requires a pre-computed x field; PKCS#8 accepts raw key bytes directly.
  const pkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Header, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);

  const publicKeyRaw = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).slice(-32));

  return { privateKey, publicKey, publicKeyRaw };
}
