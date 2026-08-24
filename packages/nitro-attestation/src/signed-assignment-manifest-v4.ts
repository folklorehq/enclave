import { createHash, createPublicKey, verify } from 'node:crypto';
import {
  ASSIGNMENT_MANIFEST_V4_DOMAIN,
  buildSignerPurposeSignatureMessage,
  signedAssignmentManifestV4Schema,
  type AssignmentManifestV4Payload,
  type SignedAssignmentManifestV4,
} from '@folklore/contracts';
import { canonicalCbor, canonicalJsonDigest, digestCanonicalCbor } from './canonical-cbor.js';
import { SignedAssignmentManifestError } from './signed-assignment-manifest.js';

export function encodeAssignmentManifestSubjectV4(input: {
  payload: AssignmentManifestV4Payload;
}): Uint8Array {
  const payload = input.payload;
  return canonicalCbor([
    ASSIGNMENT_MANIFEST_V4_DOMAIN,
    4,
    canonicalJsonDigest(payload),
    payload.generation,
    payload.orgId,
    payload.deploymentId,
    payload.poolId,
    payload.environment,
    payload.awsAccountId,
    payload.awsRegion,
  ]);
}

export function digestAssignmentManifestSubjectV4(input: {
  payload: AssignmentManifestV4Payload;
}): string {
  return digestCanonicalCbor(encodeAssignmentManifestSubjectV4(input));
}

export function verifySignedAssignmentManifestV4(
  raw: unknown,
  expectedPoolId: string,
  publicKeySpki: string,
  minimumGeneration = 1,
): SignedAssignmentManifestV4 {
  const parsed = signedAssignmentManifestV4Schema.safeParse(raw);
  if (!parsed.success) throw new SignedAssignmentManifestError('assignment_manifest_invalid');
  const envelope = parsed.data;
  if (envelope.manifest.poolId !== expectedPoolId) {
    throw new SignedAssignmentManifestError('assignment_manifest_pool_mismatch');
  }
  if (envelope.manifest.generation < minimumGeneration) {
    throw new SignedAssignmentManifestError('assignment_manifest_stale');
  }
  const subjectBytes = encodeAssignmentManifestSubjectV4({ payload: envelope.manifest });
  if (digestCanonicalCbor(subjectBytes) !== envelope.subjectDigest) {
    throw new SignedAssignmentManifestError('assignment_manifest_subject_digest_mismatch');
  }
  const publicKey = publicKeyFromSpki(publicKeySpki);
  const fingerprint = createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  if (fingerprint !== envelope.publicKeyFingerprint) {
    throw new SignedAssignmentManifestError('assignment_manifest_verifier_invalid');
  }
  const message = buildSignerPurposeSignatureMessage(
    'assignment-manifest',
    ASSIGNMENT_MANIFEST_V4_DOMAIN,
    Buffer.from(envelope.subjectDigest, 'hex'),
  );
  if (!verify(null, message, publicKey, Buffer.from(envelope.signature, 'base64'))) {
    throw new SignedAssignmentManifestError('assignment_manifest_signature_invalid');
  }
  return envelope;
}

function publicKeyFromSpki(publicKeySpki: string) {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(publicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    return publicKey;
  } catch {
    throw new SignedAssignmentManifestError('assignment_manifest_verifier_invalid');
  }
}
