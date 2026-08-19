import {
  bootManifestKeysetSchema,
  signedBootManifestKeysetSchema,
  type BootManifestKeyset,
  type SignedBootManifestKeyset,
} from '@folklore/contracts/enclave-attestation';
import { encode } from 'cborg';
import { createPublicKey, createHash, sign, verify, type KeyObject } from 'node:crypto';
import {
  BOOT_MANIFEST_MIN_KEYSET_GENERATION,
  BOOT_MANIFEST_ROOT_KEY_ID,
  BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
} from './trusted-boot-root.js';
import { assertApprovedBootManifestRoot } from './trusted-boot-root-policy.js';

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

export function resolveBootManifestKeysetMinimumGeneration(requestedGeneration?: number): number {
  if (requestedGeneration === undefined) return BOOT_MANIFEST_MIN_KEYSET_GENERATION;
  if (!Number.isSafeInteger(requestedGeneration)) {
    throw new BootManifestKeysetError('boot_manifest_keyset_invalid');
  }
  return Math.max(BOOT_MANIFEST_MIN_KEYSET_GENERATION, requestedGeneration);
}

export function verifySignedBootManifestKeyset(raw: unknown): BootManifestKeyset {
  try {
    assertApprovedBootManifestRoot();
  } catch {
    throw new BootManifestKeysetError('boot_manifest_keyset_root_invalid');
  }
  return verifySignedBootManifestKeysetWithRoot(
    raw,
    BOOT_MANIFEST_ROOT_KEY_ID,
    BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
    BOOT_MANIFEST_MIN_KEYSET_GENERATION,
  );
}

export function verifySignedBootManifestKeysetForTest(
  raw: unknown,
  rootKeyId: string,
  rootPublicKeyPem: string,
  minimumGeneration = BOOT_MANIFEST_MIN_KEYSET_GENERATION,
): BootManifestKeyset {
  return verifySignedBootManifestKeysetWithRoot(
    raw,
    rootKeyId,
    rootPublicKeyPem,
    resolveBootManifestKeysetMinimumGeneration(minimumGeneration),
  );
}

/** Test-only keyset signer: signs a keyset with a caller-supplied root key so v3 verifier tests can build real signed keysets without the pinned production root. */
export function signBootManifestKeysetForTest(
  keyset: BootManifestKeyset,
  rootPublicKeyPem: string,
  rootPrivateKey: KeyObject,
): SignedBootManifestKeyset {
  const parsed = bootManifestKeysetSchema.parse(keyset);
  const rootKey = createPublicKey(rootPublicKeyPem);
  if (rootKey.asymmetricKeyType !== 'ed25519' || rootPrivateKey.asymmetricKeyType !== 'ed25519') {
    throw new BootManifestKeysetError('boot_manifest_keyset_invalid');
  }
  const signature = sign(null, encodeBootManifestKeyset(parsed), rootPrivateKey);
  return signedBootManifestKeysetSchema.parse({
    version: 1,
    keyset: parsed,
    algorithm: 'Ed25519',
    signature: Buffer.from(signature).toString('base64'),
  });
}

function verifySignedBootManifestKeysetWithRoot(
  raw: unknown,
  rootKeyId: string,
  rootPublicKeyPem: string,
  minimumGeneration: number,
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
