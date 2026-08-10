import {
  bootManifestKeysetSchema,
  signedBootManifestKeysetSchema,
  type BootManifestKeyset,
  type SignedBootManifestKeyset,
} from '@folklore/contracts/enclave-attestation';
import { encode } from 'cborg';
import { createPublicKey, createHash, verify } from 'node:crypto';

const KEYSET_DOMAIN = 'folklore.boot-manifest-keyset.v1';

export type BootManifestKeysetVerificationFailure =
  | 'boot_manifest_keyset_invalid'
  | 'boot_manifest_keyset_signature_invalid'
  | 'boot_manifest_keyset_root_invalid';

export class BootManifestKeysetError extends Error {
  constructor(readonly code: BootManifestKeysetVerificationFailure) {
    super(code);
    this.name = 'BootManifestKeysetError';
  }
}

export function encodeBootManifestKeyset(input: BootManifestKeyset): Uint8Array {
  const keyset = bootManifestKeysetSchema.parse(input);
  const keys = [...keyset.keys]
    .sort((left, right) => left.keyId.localeCompare(right.keyId))
    .map((key) => [key.keyId, key.status, publicKeyDer(key.publicKeyPem)]);
  return encode([KEYSET_DOMAIN, keyset.version, keyset.rootKeyId, keyset.generation, keys]);
}

export function hashBootManifestKeyset(input: BootManifestKeyset): string {
  return createHash('sha256').update(encodeBootManifestKeyset(input)).digest('hex');
}

export function verifySignedBootManifestKeyset(
  raw: unknown,
  rootKeyId: string,
  rootPublicKeyPem: string,
  minimumGeneration = 1,
): BootManifestKeyset {
  const parsed = signedBootManifestKeysetSchema.safeParse(raw);
  if (!parsed.success || parsed.data.keyset.rootKeyId !== rootKeyId) {
    throw new BootManifestKeysetError('boot_manifest_keyset_invalid');
  }
  if (!Number.isSafeInteger(minimumGeneration) || minimumGeneration < 1) {
    throw new BootManifestKeysetError('boot_manifest_keyset_invalid');
  }
  if (parsed.data.keyset.generation < minimumGeneration) {
    throw new BootManifestKeysetError('boot_manifest_keyset_invalid');
  }
  let rootKey;
  try {
    rootKey = createPublicKey(rootPublicKeyPem);
    if (rootKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('wrong root type');
    }
  } catch {
    throw new BootManifestKeysetError('boot_manifest_keyset_root_invalid');
  }
  const valid = verify(
    null,
    encodeBootManifestKeyset(parsed.data.keyset),
    rootKey,
    Buffer.from(parsed.data.signature, 'base64'),
  );
  if (!valid) throw new BootManifestKeysetError('boot_manifest_keyset_signature_invalid');
  return freezeKeyset(parsed.data.keyset);
}

function publicKeyDer(publicKeyPem: string): Uint8Array {
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    const der = key.export({ type: 'spki', format: 'der' });
    if (!Buffer.isBuffer(der) || der.byteLength !== 44) throw new Error('wrong key size');
    return new Uint8Array(der);
  } catch {
    throw new BootManifestKeysetError('boot_manifest_keyset_invalid');
  }
}

function freezeKeyset(keyset: BootManifestKeyset): BootManifestKeyset {
  const keys = keyset.keys.map((key) => Object.freeze({ ...key }));
  return Object.freeze({ ...keyset, keys: Object.freeze(keys) }) as unknown as BootManifestKeyset;
}
