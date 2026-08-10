import { createHash, createPublicKey, verify } from 'node:crypto';
import {
  assignmentManifestSignaturePayload,
  type SignedAssignmentManifest,
} from '@folklore/contracts';

const verifiedAssignmentManifestBrand = Symbol('verifiedAssignmentManifest');

export type VerifiedAssignmentManifest = SignedAssignmentManifest & {
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
  if (!signedPublicKey || !configuredPublicKey) {
    throw new Error('assignment_manifest_verifier_unavailable');
  }
  if (canonicalAssignmentManifestPublicKeySpki(configuredPublicKey) !== signedPublicKey) {
    throw new Error('assignment_manifest_verifier_mismatch');
  }
  return signedPublicKey;
}

export function verifyAssignmentManifest(
  manifest: SignedAssignmentManifest,
  assignmentManifestPublicKeySpki: string,
): VerifiedAssignmentManifest {
  const { digest, signature, ...unsigned } = manifest;
  const expectedDigest = createHash('sha256').update(JSON.stringify(unsigned)).digest('hex');
  if (expectedDigest !== digest) throw new Error('assignment_manifest_digest_invalid');
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(assignmentManifestPublicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('assignment_manifest_verifier_invalid');
  }
  const valid = verify(
    null,
    Buffer.from(assignmentManifestSignaturePayload(digest), 'utf8'),
    publicKey,
    Buffer.from(signature.signature, 'base64'),
  );
  if (!valid) throw new Error('assignment_manifest_signature_invalid');
  return Object.freeze({
    ...manifest,
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
