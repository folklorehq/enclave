import { hkdfSync, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { entropyToMnemonic } from 'bip39';
import { HELP_CENTER_MAX_SIGNING_EPOCH } from '@folklore/contracts/help-center';
import { sha256Hex } from '@folklore/utils';

const LLM_CACHE_NAME_KEY_PURPOSE = 'llm-cache-name-v1';
const HELP_CENTER_INTEGRITY_KEY_PURPOSE = 'help-center-integrity-v1';
const HELP_CENTER_SLUG_KEY_PURPOSE = 'help-center-slug-v1';
const HELP_CENTER_RELEASE_KEY_PURPOSE = 'help-center-release-v1:epoch-';
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_RAW_PUBLIC_KEY_LENGTH = 32;

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

export interface HelpCenterSigningKey {
  readonly privateKey: KeyObject;
  readonly publicKeyRaw: Buffer;
  readonly keyId: string;
  readonly epoch: number;
}

export function deriveHelpCenterIntegrityKey(masterKey: Buffer): Buffer {
  return deriveKey(masterKey, HELP_CENTER_INTEGRITY_KEY_PURPOSE);
}

export function deriveHelpCenterSlugKey(masterKey: Buffer): Buffer {
  return deriveKey(masterKey, HELP_CENTER_SLUG_KEY_PURPOSE);
}

// The caller owns the returned KeyObject and must not keep it past the call.
export function deriveHelpCenterSigningKey(masterKey: Buffer, epoch: number): HelpCenterSigningKey {
  if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > HELP_CENTER_MAX_SIGNING_EPOCH) {
    throw new Error('help_center_signing_epoch_invalid');
  }
  const seed = deriveKey(masterKey, `${HELP_CENTER_RELEASE_KEY_PURPOSE}${epoch}`);
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  try {
    const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    const publicKeyRaw = Buffer.from(
      createPublicKey(privateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-ED25519_RAW_PUBLIC_KEY_LENGTH),
    );
    return { privateKey, publicKeyRaw, keyId: sha256Hex(publicKeyRaw), epoch };
  } finally {
    seed.fill(0);
    der.fill(0);
  }
}
