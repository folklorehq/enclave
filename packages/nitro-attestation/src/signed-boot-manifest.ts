import {
  signedBootManifestSchema,
  signedBootManifestV3Schema,
  type BootManifest,
  type BootManifestKeyset,
  type SignedBootManifestV3,
} from '@folklore/contracts/enclave-attestation';
import { createPublicKey, createHash, verify } from 'node:crypto';
import {
  encodeBootManifest,
  encodeBootManifestSubjectV3,
  digestCanonicalCbor,
} from './canonical-cbor.js';
import { hashBootManifestKeyset, verifySignedBootManifestKeyset } from './boot-manifest-keyset.js';
import { buildSignerPurposeSignatureMessage } from '@folklore/contracts';

export type SignedBootManifestVerificationFailure =
  | 'boot_manifest_invalid'
  | 'boot_manifest_key_unavailable'
  | 'boot_manifest_key_revoked'
  | 'boot_manifest_keyset_generation_mismatch'
  | 'boot_manifest_keyset_digest_mismatch'
  | 'boot_manifest_subject_digest_mismatch'
  | 'boot_manifest_signature_invalid';

export class SignedBootManifestError extends Error {
  constructor(readonly code: SignedBootManifestVerificationFailure) {
    super(code);
    this.name = 'SignedBootManifestError';
  }
}

export interface VerifiedSignedBootManifest {
  manifest: BootManifest;
  keyset: BootManifestKeyset;
}

export function verifySignedBootManifest(
  rawManifest: unknown,
  rawKeyset: unknown,
): VerifiedSignedBootManifest {
  let keyset: BootManifestKeyset;
  try {
    keyset = verifySignedBootManifestKeyset(rawKeyset);
  } catch {
    throw new SignedBootManifestError('boot_manifest_invalid');
  }
  const parsed = signedBootManifestSchema.safeParse(rawManifest);
  if (!parsed.success) throw new SignedBootManifestError('boot_manifest_invalid');
  const key = keyset.keys.find((candidate) => candidate.keyId === parsed.data.manifest.signerKeyId);
  if (!key) throw new SignedBootManifestError('boot_manifest_key_unavailable');
  if (key.status !== 'active' && key.status !== 'verification-only') {
    throw new SignedBootManifestError('boot_manifest_key_revoked');
  }
  let publicKey;
  try {
    publicKey = createPublicKey(key.publicKeyPem);
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
  } catch {
    throw new SignedBootManifestError('boot_manifest_invalid');
  }
  const valid = verify(
    null,
    encodeBootManifest(parsed.data.manifest),
    publicKey,
    Buffer.from(parsed.data.signature, 'base64'),
  );
  if (!valid) throw new SignedBootManifestError('boot_manifest_signature_invalid');
  return { manifest: parsed.data.manifest, keyset };
}

export interface VerifiedSignedBootManifestV3 {
  manifest: BootManifest;
  keyset: BootManifestKeyset;
  signed: SignedBootManifestV3;
}

// v3 boot verification: the signature covers the purpose message over the subject digest, and the
// envelope's key identity must match the verified keyset. The subject is canonical-CBOR-encoded
// exactly once from the unsigned manifest plus the explicit scope fields. `verifyKeyset` defaults
// to the pinned-root verifier; tests inject a root of their own.
export function verifySignedBootManifestV3(
  rawManifest: unknown,
  rawKeyset: unknown,
  options: { verifyKeyset?: (raw: unknown) => BootManifestKeyset } = {},
): VerifiedSignedBootManifestV3 {
  let keyset: BootManifestKeyset;
  try {
    keyset = (options.verifyKeyset ?? verifySignedBootManifestKeyset)(rawKeyset);
  } catch {
    throw new SignedBootManifestError('boot_manifest_invalid');
  }
  const parsed = signedBootManifestV3Schema.safeParse(rawManifest);
  if (!parsed.success) throw new SignedBootManifestError('boot_manifest_invalid');
  const envelope = parsed.data;
  const key = keyset.keys.find((candidate) => candidate.keyId === envelope.manifest.signerKeyId);
  if (!key) throw new SignedBootManifestError('boot_manifest_key_unavailable');
  if (key.status !== 'active' && key.status !== 'verification-only') {
    throw new SignedBootManifestError('boot_manifest_key_revoked');
  }
  if (envelope.keyId !== key.keyId) throw new SignedBootManifestError('boot_manifest_invalid');
  if (envelope.keysetGeneration !== keyset.generation) {
    throw new SignedBootManifestError('boot_manifest_keyset_generation_mismatch');
  }
  if (envelope.keysetDigest !== hashBootManifestKeyset(keyset)) {
    throw new SignedBootManifestError('boot_manifest_keyset_digest_mismatch');
  }
  let publicKey;
  let publicKeyDer: Buffer;
  try {
    publicKey = createPublicKey(key.publicKeyPem);
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  } catch {
    throw new SignedBootManifestError('boot_manifest_invalid');
  }
  if (createHash('sha256').update(publicKeyDer).digest('hex') !== envelope.publicKeyFingerprint) {
    throw new SignedBootManifestError('boot_manifest_invalid');
  }
  const subjectBytes = encodeBootManifestSubjectV3({
    manifest: envelope.manifest,
    scope: envelope.scope,
  });
  if (digestCanonicalCbor(subjectBytes) !== envelope.subjectDigest) {
    throw new SignedBootManifestError('boot_manifest_subject_digest_mismatch');
  }
  const message = buildSignerPurposeSignatureMessage(
    'boot-manifest',
    envelope.domain,
    Buffer.from(envelope.subjectDigest, 'hex'),
  );
  const valid = verify(null, message, publicKey, Buffer.from(envelope.signature, 'base64'));
  if (!valid) throw new SignedBootManifestError('boot_manifest_signature_invalid');
  return { manifest: envelope.manifest, keyset, signed: envelope };
}

export type ParsedBootManifestWireResult =
  | { wire: 'LegacySignedBootManifestV2'; manifest: BootManifest; keyset: BootManifestKeyset }
  | { wire: 'SignedBootManifestV3'; manifest: BootManifest; keyset: BootManifestKeyset };

/** Discriminated dual-read boot verifier: v2 and v3 are the only accepted boot wires. */
export function verifySignedBootManifestWire(
  rawManifest: unknown,
  rawKeyset: unknown,
): ParsedBootManifestWireResult {
  const v3 = verifySignedBootManifestV3Safe(rawManifest, rawKeyset);
  if (v3) return v3;
  const v2 = verifySignedBootManifest(rawManifest, rawKeyset);
  return { wire: 'LegacySignedBootManifestV2', manifest: v2.manifest, keyset: v2.keyset };
}

function verifySignedBootManifestV3Safe(
  rawManifest: unknown,
  rawKeyset: unknown,
): ParsedBootManifestWireResult | null {
  try {
    const verified = verifySignedBootManifestV3(rawManifest, rawKeyset);
    return { wire: 'SignedBootManifestV3', manifest: verified.manifest, keyset: verified.keyset };
  } catch {
    return null;
  }
}
