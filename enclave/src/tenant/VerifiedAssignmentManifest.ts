import { createHash, createPublicKey, verify } from 'node:crypto';
import {
  assignmentManifestDigestPayload,
  assignmentManifestSignaturePayload,
  versionedAssignmentManifestSchema,
  type LegacySignedAssignmentManifestV1,
  type NormalizedAssignmentManifestV1,
} from '@folklore/contracts';
import { verifyAssignmentManifestWire as verifyWire } from '@folklore/nitro-attestation';

const verifiedAssignmentManifestBrand = Symbol('verifiedAssignmentManifest');

// The branded verified assignment manifest is the NORMALIZED wire result (plan migration rule 2):
// every reader parses the same union, verifies the wire-native signature, and consumes the same
// poolId/generation/digest/assignments shape regardless of which wire delivered it.
export type VerifiedAssignmentManifest = Readonly<NormalizedAssignmentManifestV1> & {
  readonly [verifiedAssignmentManifestBrand]: true;
};

export function canonicalAssignmentManifestPublicKeySpki(value: string): string {
  let publicKey;
  try {
    publicKey = createPublicKey(value);
  } catch {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  if (!Buffer.isBuffer(spki) || spki.byteLength !== 44) {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  return spki.toString('base64');
}

export function assignmentManifestPublicKeyForVerifiedBoot(
  bootManifest: { assignmentManifestPublicKeySpki?: string } | undefined,
  configuredPublicKey: string,
): string {
  const signedPublicKey = bootManifest?.assignmentManifestPublicKeySpki;
  if (!signedPublicKey) {
    throw new Error('assignment_manifest_verifier_unavailable');
  }
  if (!configuredPublicKey) return signedPublicKey;
  if (canonicalAssignmentManifestPublicKeySpki(configuredPublicKey) !== signedPublicKey) {
    throw new Error('assignment_manifest_verifier_mismatch');
  }
  return signedPublicKey;
}

/** Legacy-shaped verification for the versioned assignment wire; returns the normalized branded manifest. */
export function verifyAssignmentManifest(
  manifest: LegacySignedAssignmentManifestV1,
  assignmentManifestPublicKeySpki: string,
): VerifiedAssignmentManifest {
  const parsed = versionedAssignmentManifestSchema.parse(manifest);
  const { digest, signature, ...unsigned } = parsed;
  const expectedDigest = createHash('sha256')
    .update(assignmentManifestDigestPayload(unsigned))
    .digest('hex');
  if (expectedDigest !== digest) throw new Error('assignment_manifest_digest_invalid');
  const publicKey = publicKeyFromSpki(assignmentManifestPublicKeySpki);
  const valid = verify(
    null,
    Buffer.from(assignmentManifestSignaturePayload(digest), 'utf8'),
    publicKey,
    Buffer.from(signature.signature, 'base64'),
  );
  if (!valid) throw new Error('assignment_manifest_signature_invalid');
  return brandNormalized({
    wire: 'LegacySignedAssignmentManifestV1',
    payloadName: null,
    poolId: parsed.poolId,
    generation: parsed.generation,
    digest,
    assignments: parsed.assignments.map((assignment) => ({ ...assignment })),
    ...(parsed.runtimeDatabase ? { runtimeDatabase: parsed.runtimeDatabase } : {}),
    ...(parsed.inferenceAttestation ? { inferenceAttestation: parsed.inferenceAttestation } : {}),
    raw: parsed,
  });
}

/** Wire-native verification of an already-parsed discriminated result (v3, V2, or legacy v1). */
export function verifyAssignmentManifestWire(
  parsed: NormalizedAssignmentManifestV1,
  assignmentManifestPublicKeySpki: string,
): VerifiedAssignmentManifest {
  const verified = verifyWire(parsed.raw, parsed.poolId, assignmentManifestPublicKeySpki, {
    lastGeneration: parsed.generation - 1,
  });
  if (verified.digest !== parsed.digest) throw new Error('assignment_manifest_digest_invalid');
  return brandNormalized(verified);
}

function brandNormalized(value: NormalizedAssignmentManifestV1): VerifiedAssignmentManifest {
  return Object.freeze({
    ...value,
    assignments: Object.freeze(
      value.assignments.map((assignment) => Object.freeze({ ...assignment })),
    ),
    [verifiedAssignmentManifestBrand]: true,
  }) as VerifiedAssignmentManifest;
}

export function isVerifiedAssignmentManifest(value: unknown): value is VerifiedAssignmentManifest {
  return (
    typeof value === 'object' &&
    value !== null &&
    verifiedAssignmentManifestBrand in value &&
    value[verifiedAssignmentManifestBrand] === true
  );
}

function publicKeyFromSpki(publicKeySpki: string) {
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(publicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  return publicKey;
}
