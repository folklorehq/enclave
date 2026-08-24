import { createHash, createPublicKey, verify } from 'node:crypto';

import {
  parseSignerFloorAuthorityV2,
  parseSignerFloorCommitV2,
  signerFloorCommitSubjectBytesV2,
  type SignerFloorAuthorityV2,
  type SignerFloorCommitV2,
} from '@folklore/contracts';

export interface SignerFloorCommitVerificationInputV2 {
  readonly commit: SignerFloorCommitV2;
  readonly publicKeyDer: Uint8Array;
  readonly expectedAuthority: SignerFloorAuthorityV2;
}

export function verifySignerFloorCommitV2(input: SignerFloorCommitVerificationInputV2): void {
  const commit = parseSignerFloorCommitV2(input.commit);
  const expectedAuthority = parseSignerFloorAuthorityV2(input.expectedAuthority);
  const subject = commit.subject;

  if (
    subject.authorityKmsKeyArn !== expectedAuthority.kmsKeyArn ||
    subject.authorityPublicKeySpkiDerSha256 !== expectedAuthority.publicKeySpkiDerSha256 ||
    subject.authorityRootEpoch !== expectedAuthority.rootEpoch ||
    subject.environment !== expectedAuthority.environment ||
    subject.awsAccountId !== expectedAuthority.awsAccountId ||
    subject.awsRegion !== expectedAuthority.awsRegion
  ) {
    throw new Error('signer_floor_authority_mismatch');
  }

  if (input.publicKeyDer.byteLength !== 44) {
    throw new Error('signer_floor_authority_public_key_invalid');
  }

  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(input.publicKeyDer),
      format: 'der',
      type: 'spki',
    });
  } catch {
    throw new Error('signer_floor_authority_public_key_invalid');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('signer_floor_authority_public_key_invalid');
  }

  const publicKeyFingerprint = createHash('sha256')
    .update(Buffer.from(input.publicKeyDer))
    .digest('hex');
  if (publicKeyFingerprint !== expectedAuthority.publicKeySpkiDerSha256) {
    throw new Error('signer_floor_authority_public_key_mismatch');
  }

  const signature = Buffer.from(commit.signature, 'base64');
  if (signature.byteLength !== 64) {
    throw new Error('signer_floor_commit_signature_invalid');
  }
  const valid = verify(
    null,
    Buffer.from(signerFloorCommitSubjectBytesV2(subject)),
    publicKey,
    signature,
  );
  if (!valid) throw new Error('signer_floor_commit_signature_invalid');
}
