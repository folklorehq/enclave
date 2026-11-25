import {
  parseAssignmentManifestWire,
  signedAssignmentManifestV3Schema,
  type NormalizedAssignmentManifestV1,
  type SignedAssignmentManifestV3,
} from '@folklore/contracts';
import { createPublicKey, verify } from 'node:crypto';
import { buildSignerPurposeSignatureMessage } from '@folklore/contracts';
import { encodeAssignmentManifestSubjectV3, digestCanonicalCbor } from './canonical-cbor.js';
import { verifySignedAssignmentManifestV4 } from './signed-assignment-manifest-v4.js';

type SignedAssignmentManifestVerificationFailure =
  | 'assignment_manifest_invalid'
  | 'assignment_manifest_pool_mismatch'
  | 'assignment_manifest_stale'
  | 'assignment_manifest_verifier_invalid'
  | 'assignment_manifest_subject_digest_mismatch'
  | 'assignment_manifest_signature_invalid';

export class SignedAssignmentManifestError extends Error {
  constructor(readonly code: SignedAssignmentManifestVerificationFailure) {
    super(code);
    this.name = 'SignedAssignmentManifestError';
  }
}

export function publicKeyFromSpki(publicKeySpki: string) {
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(publicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
  } catch {
    throw new SignedAssignmentManifestError('assignment_manifest_verifier_invalid');
  }
  return publicKey;
}

// v3 assignment verification: the subject digest is recomputed from the unsigned payload (canonical
// CBOR, exactly once) and the signature covers the purpose message over that digest.
export function verifySignedAssignmentManifestV3(
  raw: unknown,
  expectedPoolId: string,
  publicKeySpki: string,
  minimumGeneration = 1,
): SignedAssignmentManifestV3 {
  const parsed = signedAssignmentManifestV3Schema.safeParse(raw);
  if (!parsed.success) throw new SignedAssignmentManifestError('assignment_manifest_invalid');
  const envelope = parsed.data;
  if (envelope.manifest.poolId !== expectedPoolId) {
    throw new SignedAssignmentManifestError('assignment_manifest_pool_mismatch');
  }
  if (envelope.manifest.generation < minimumGeneration) {
    throw new SignedAssignmentManifestError('assignment_manifest_stale');
  }
  const subjectBytes = encodeAssignmentManifestSubjectV3({ payload: envelope.manifest });
  if (digestCanonicalCbor(subjectBytes) !== envelope.subjectDigest) {
    throw new SignedAssignmentManifestError('assignment_manifest_subject_digest_mismatch');
  }
  const message = buildSignerPurposeSignatureMessage(
    'assignment-manifest',
    envelope.domain,
    Buffer.from(envelope.subjectDigest, 'hex'),
  );
  const publicKey = publicKeyFromSpki(publicKeySpki);
  const valid = verify(null, message, publicKey, Buffer.from(envelope.signature, 'base64'));
  if (!valid) throw new SignedAssignmentManifestError('assignment_manifest_signature_invalid');
  return envelope;
}

interface VerifyAssignmentManifestWireOptions {
  lastGeneration: number;
}

/** Verifies the signed V4 and V3 assignment wires and preserves their normalized discriminants. */
export function verifyAssignmentManifestWire(
  raw: unknown,
  expectedPoolId: string,
  publicKeySpki: string,
  options: VerifyAssignmentManifestWireOptions,
): NormalizedAssignmentManifestV1 {
  const parsed = parseAssignmentManifestWire(raw, expectedPoolId, {
    lastGeneration: options.lastGeneration,
  });
  switch (parsed.wire) {
    case 'SignedAssignmentManifestV4':
      verifySignedAssignmentManifestV4(
        parsed.raw,
        expectedPoolId,
        publicKeySpki,
        options.lastGeneration + 1,
      );
      return parsed;
    case 'SignedAssignmentManifestV3':
      verifySignedAssignmentManifestV3(
        parsed.raw,
        expectedPoolId,
        publicKeySpki,
        options.lastGeneration + 1,
      );
      return parsed;
    default:
      throw new SignedAssignmentManifestError('assignment_manifest_invalid');
  }
}
