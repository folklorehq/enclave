import {
  assignmentManifestDigestPayload,
  assignmentManifestSignaturePayload,
  assignmentManifestV2Payload,
  canonicalJson,
  legacyAssignmentReadFloorV1Schema,
  parseAssignmentManifestWire,
  signedAssignmentManifestV3Schema,
  versionedAssignmentManifestSchema,
  type AssignmentManifestV2,
  type LegacyAssignmentKeyRecordV1,
  type LegacyAssignmentReadFloorV1,
  type LegacySignedAssignmentManifestV1,
  type NormalizedAssignmentManifestV1,
  type SignedAssignmentManifestV3,
} from '@folklore/contracts';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { buildSignerPurposeSignatureMessage } from '@folklore/contracts';
import { encodeAssignmentManifestSubjectV3, digestCanonicalCbor } from './canonical-cbor.js';

export type SignedAssignmentManifestVerificationFailure =
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

export function verifySignedAssignmentManifest(
  raw: unknown,
  expectedPoolId: string,
  publicKeySpki: string,
  minimumGeneration = 1,
): LegacySignedAssignmentManifestV1 {
  const parsed = versionedAssignmentManifestSchema.safeParse(raw);
  if (!parsed.success) throw new SignedAssignmentManifestError('assignment_manifest_invalid');
  if (parsed.data.poolId !== expectedPoolId) {
    throw new SignedAssignmentManifestError('assignment_manifest_pool_mismatch');
  }
  if (parsed.data.generation < minimumGeneration) {
    throw new SignedAssignmentManifestError('assignment_manifest_stale');
  }
  const { digest, signature, ...unsigned } = parsed.data;
  const expectedDigest = createHash('sha256')
    .update(assignmentManifestDigestPayload(unsigned))
    .digest('hex');
  if (expectedDigest !== digest) {
    throw new SignedAssignmentManifestError('assignment_manifest_invalid');
  }
  const publicKey = publicKeyFromSpki(publicKeySpki);
  const valid = verify(
    null,
    Buffer.from(assignmentManifestSignaturePayload(digest), 'utf8'),
    publicKey,
    Buffer.from(signature.signature, 'base64'),
  );
  if (!valid) throw new SignedAssignmentManifestError('assignment_manifest_signature_invalid');
  return parsed.data;
}

function publicKeyFromSpki(publicKeySpki: string) {
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

export interface VerifyAssignmentManifestWireOptions {
  lastGeneration: number;
  floor?: LegacyAssignmentReadFloorV1 | null;
  keyRecord?: LegacyAssignmentKeyRecordV1 | null;
}

/** Discriminated dual-read assignment verifier: the three non-colliding wires, floor-bounded for legacy/current reads (plan migration rule 2/4). */
export function verifyAssignmentManifestWire(
  raw: unknown,
  expectedPoolId: string,
  publicKeySpki: string,
  options: VerifyAssignmentManifestWireOptions,
): NormalizedAssignmentManifestV1 {
  const floor = options.floor
    ? legacyAssignmentReadFloorV1Schema.parse(options.floor)
    : (options.floor ?? null);
  const parsed = parseAssignmentManifestWire(raw, expectedPoolId, {
    lastGeneration: options.lastGeneration,
    floor,
    keyRecord: options.keyRecord,
  });
  switch (parsed.wire) {
    case 'SignedAssignmentManifestV3': {
      const envelope = parsed.raw as SignedAssignmentManifestV3;
      verifySignedAssignmentManifestV3(
        envelope,
        expectedPoolId,
        publicKeySpki,
        options.lastGeneration + 1,
      );
      return parsed;
    }
    case 'AssignmentManifestV2': {
      const signed = parsed.raw as AssignmentManifestV2;
      verifyAssignmentManifestV2Signature(signed, publicKeySpki);
      return parsed;
    }
    case 'LegacySignedAssignmentManifestV1': {
      const signed = parsed.raw as LegacySignedAssignmentManifestV1;
      verifySignedAssignmentManifest(
        signed,
        expectedPoolId,
        publicKeySpki,
        options.lastGeneration + 1,
      );
      return parsed;
    }
  }
}

function verifyAssignmentManifestV2Signature(
  signed: AssignmentManifestV2,
  publicKeySpki: string,
): void {
  const { digest, signature, ...content } = signed;
  const contentDigest = createHash('sha256').update(canonicalJson(content), 'utf8').digest('hex');
  if (contentDigest !== digest) {
    throw new SignedAssignmentManifestError('assignment_manifest_invalid');
  }
  const publicKey = publicKeyFromSpki(publicKeySpki);
  const valid = verify(
    null,
    Buffer.from(assignmentManifestV2Payload(signed), 'utf8'),
    publicKey,
    Buffer.from(signature.signature, 'base64'),
  );
  if (!valid) throw new SignedAssignmentManifestError('assignment_manifest_signature_invalid');
}
