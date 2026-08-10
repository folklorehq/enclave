// Customer-sole-holder recovery: the master-key BIP39 mnemonic is sealed to a
// customer-provided X25519 public key so Folklore stores only ciphertext it cannot open.
// Domain-separated from ingest (`folklore-recovery-v1:`) so a recovery box is never
// interchangeable with an ingest payload. Scheme mirrors enclave/src/ingest/receiver.ts.
import {
  diffieHellman,
  hkdfSync,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'crypto';
import { deriveMnemonic } from './keygen.js';

const RECOVERY_INFO_PREFIX = Buffer.from('folklore-recovery-v1:');
const X25519_RAW_KEY_BYTES = 32;
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;

export interface RecoverySealedBox {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

function rawPublicKeyBytes(key: KeyObject): Buffer {
  return Buffer.from(key.export({ type: 'spki', format: 'der' }).slice(-X25519_RAW_KEY_BYTES));
}

function deriveAesKey(
  sharedSecret: Buffer,
  ephemeralPubBytes: Buffer,
  recipientPubBytes: Buffer,
): Buffer {
  const info = Buffer.concat([RECOVERY_INFO_PREFIX, ephemeralPubBytes, recipientPubBytes]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), info, AES_KEY_BYTES));
}

export function parseRecoveryPublicKey(hex: string): KeyObject {
  const raw = Buffer.from(hex, 'hex');
  if (raw.length !== X25519_RAW_KEY_BYTES) {
    throw new Error(
      `recovery public key must be a ${X25519_RAW_KEY_BYTES}-byte raw X25519 key (hex); got ${raw.length} bytes`,
    );
  }
  return createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') },
    format: 'jwk',
  });
}

// Recovery is the one master-key path the PCR gate does not cover: whoever holds the private half
// of this key can decrypt the sealed mnemonic and reach all content. So in production the key must
// come from the root-signed boot manifest, never from the parent-written env file — a parent that
// substitutes its own key gets a refused boot, not a decryptable mnemonic (audit F2). Dev and test
// have no manifest signer, so they still take the env value.
export function assertRecoveryConfigured(hex: string, signed?: string): KeyObject {
  const envKey = normalizeRecoveryKey(hex);
  const signedKey = normalizeRecoveryKey(signed);
  if (signedKey && envKey && signedKey !== envKey) {
    throw new Error('refusing first boot: RECOVERY_PUBKEY disagrees with the signed boot manifest');
  }
  if (!signedKey && requiresSignedRecoveryKey()) {
    throw new Error(
      'refusing first boot: the signed boot manifest carries no recovery public key, and a production enclave will not seal the master-key mnemonic to a parent-chosen one',
    );
  }
  const chosen = signedKey || envKey;
  if (!chosen) {
    throw new Error(
      'refusing first boot: no customer recovery public key configured (RECOVERY_PUBKEY)',
    );
  }
  return parseRecoveryPublicKey(chosen);
}

// entrypoint.sh pins NODE_ENV=production after parsing the parent's env file, so the parent cannot
// claim to be a dev run to reach the env-key path.
//
// Deliberately not scoped to "a boot manifest was configured": the parent decides whether the
// manifest env vars arrive at all, so gating on their presence would hand it the downgrade this
// check exists to refuse. Shared pools receive this evidence only from their verified versioned
// assignment manifest, never directly from an env assignment.
function requiresSignedRecoveryKey(): boolean {
  return process.env['NODE_ENV'] === 'production';
}

// Hex case is not identity: an env value and a manifest value that differ only in case name the
// same key, and treating them as a disagreement would refuse a legitimate boot.
function normalizeRecoveryKey(value: string | undefined): string {
  return value?.trim().toLowerCase() ?? '';
}

export function sealToRecoveryKey(
  plaintext: Buffer,
  recipientPublicKey: KeyObject,
): RecoverySealedBox {
  const recipientPubBytes = rawPublicKeyBytes(recipientPublicKey);
  const { privateKey: ephemeralPriv, publicKey: ephemeralPub } = generateKeyPairSync('x25519');
  const ephemeralPubBytes = rawPublicKeyBytes(ephemeralPub);

  const sharedSecret = diffieHellman({ privateKey: ephemeralPriv, publicKey: recipientPublicKey });
  const aesKey = deriveAesKey(sharedSecret, ephemeralPubBytes, recipientPubBytes);

  const nonce = randomBytes(GCM_NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  sharedSecret.fill(0);
  aesKey.fill(0);

  return {
    ephemeralPublicKey: ephemeralPubBytes.toString('hex'),
    nonce: nonce.toString('hex'),
    ciphertext: Buffer.concat([encrypted, authTag]).toString('hex'),
  };
}

// Reference decryptor for the recovery runbook and round-trip tests; the enclave never
// holds the recipient private key, so this path never runs in production.
export function openRecoveryBox(box: RecoverySealedBox, recipientPrivateKey: KeyObject): Buffer {
  const ephemeralPubBytes = Buffer.from(box.ephemeralPublicKey, 'hex');
  const nonce = Buffer.from(box.nonce, 'hex');
  const ciphertextWithTag = Buffer.from(box.ciphertext, 'hex');

  const ephemeralPub = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: ephemeralPubBytes.toString('base64url') },
    format: 'jwk',
  });

  const sharedSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPub });
  const recipientPubBytes = rawPublicKeyBytes(createPublicKey(recipientPrivateKey));
  const aesKey = deriveAesKey(sharedSecret, ephemeralPubBytes, recipientPubBytes);

  const authTag = ciphertextWithTag.slice(-GCM_TAG_BYTES);
  const ciphertext = ciphertextWithTag.slice(0, -GCM_TAG_BYTES);

  const decipher = createDecipheriv('aes-256-gcm', aesKey, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// The master key itself must persist for the process lifetime, so it is not zeroed here.
export function sealRecoveryMnemonic(
  masterKey: Buffer,
  recipientPublicKey: KeyObject,
): RecoverySealedBox {
  const mnemonicBytes = Buffer.from(deriveMnemonic(masterKey), 'utf8');
  try {
    return sealToRecoveryKey(mnemonicBytes, recipientPublicKey);
  } finally {
    mnemonicBytes.fill(0);
  }
}
