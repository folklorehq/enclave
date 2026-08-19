import { createHash, createPublicKey, type KeyObject } from 'node:crypto';
import {
  BOOT_MANIFEST_MIN_KEYSET_GENERATION,
  BOOT_MANIFEST_ROOT_KEY_ID,
  BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
} from './trusted-boot-root.js';

const PLACEHOLDER_ROOT_KEY_ID: string = 'offline-root-2026-08';
const PLACEHOLDER_ROOT_DER_SPKI_SHA256 =
  '49084fc7fc44966b63e8851b3ff5413eecf0641f980616be10d061dfaae8edc5';

// The approved root pin. The installed root (trusted-boot-root.ts) must equal this exact
// identity, so a future edit that swaps in any other valid Ed25519 key fails closed here and in
// CI, rather than silently re-anchoring trust. Update both together via a reviewed root ceremony.
const APPROVED_ROOT_KEY_ID = 'folklore-boot-root-kms-2026-08';
const APPROVED_ROOT_DER_SPKI_SHA256 =
  '0d454f42fd96e8de65b0a3fc2772bceffc09c11286e5e048f5386d7ffe09bf50';

export interface BootManifestRootIdentity {
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly derSpkiSha256: string;
  readonly minimumKeysetGeneration: number;
}

export const BOOT_MANIFEST_ROOT_DER_SPKI_SHA256 = sha256Spki(BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM);

export function getBootManifestRootIdentity(): BootManifestRootIdentity {
  return Object.freeze({
    keyId: BOOT_MANIFEST_ROOT_KEY_ID,
    publicKeyPem: BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
    derSpkiSha256: BOOT_MANIFEST_ROOT_DER_SPKI_SHA256,
    minimumKeysetGeneration: BOOT_MANIFEST_MIN_KEYSET_GENERATION,
  });
}

export function assertApprovedBootManifestRoot(): void {
  const fingerprint = BOOT_MANIFEST_ROOT_DER_SPKI_SHA256;
  const installedKeyId: string = BOOT_MANIFEST_ROOT_KEY_ID;
  // Reject the fail-closed placeholder outright.
  if (
    installedKeyId === PLACEHOLDER_ROOT_KEY_ID ||
    fingerprint === PLACEHOLDER_ROOT_DER_SPKI_SHA256
  ) {
    throw new Error('boot_manifest_root_unapproved');
  }
  // Positive allowlist: the installed root must match the approved pin exactly.
  if (installedKeyId !== APPROVED_ROOT_KEY_ID || fingerprint !== APPROVED_ROOT_DER_SPKI_SHA256) {
    throw new Error('boot_manifest_root_unapproved');
  }
}

function sha256Spki(value: string | KeyObject): string {
  const key = typeof value === 'string' ? parseEd25519PublicKey(value) : value;
  const der = key.export({ type: 'spki', format: 'der' });
  if (!Buffer.isBuffer(der)) throw new Error('boot_manifest_root_invalid');
  return createHash('sha256').update(der).digest('hex');
}

function parseEd25519PublicKey(publicKeyPem: string): KeyObject {
  if (typeof publicKeyPem !== 'string' || /PRIVATE KEY/.test(publicKeyPem)) {
    throw new Error('boot_manifest_root_invalid');
  }
  try {
    const key = createPublicKey(publicKeyPem);
    const der = key.export({ type: 'spki', format: 'der' });
    if (
      key.type !== 'public' ||
      key.asymmetricKeyType !== 'ed25519' ||
      !Buffer.isBuffer(der) ||
      der.byteLength !== 44
    ) {
      throw new Error('boot_manifest_root_invalid');
    }
    return key;
  } catch (error: unknown) {
    if (error instanceof Error && error.message === 'boot_manifest_root_invalid') throw error;
    throw new Error('boot_manifest_root_invalid');
  }
}
