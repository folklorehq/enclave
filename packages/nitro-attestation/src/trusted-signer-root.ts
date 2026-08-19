import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalJson } from '@folklore/contracts';
import { canonicalCbor } from './canonical-cbor.js';

// The independently pinned normal signer root (plan "Keyset, roots, recovery installation, and
// reader capability"): exactly three active Ed25519 members, threshold 2-of-3. Incoming keysets can
// never replace this member set. The pinned artifact carries public material only; tests build their
// own roots with fresh keys via `buildTrustedSignerRoot`.

export const TRUSTED_SIGNER_ROOT_MEMBER_COUNT = 3 as const;
export const TRUSTED_SIGNER_ROOT_THRESHOLD = 2 as const;

export interface TrustedSignerRootMemberV1 {
  readonly memberId: string;
  readonly publicKeyPem: string;
  readonly publicKeySpkiDerSha256: string;
}

export interface TrustedSignerRootV1 {
  readonly schema: 'TrustedSignerRootV1';
  readonly version: 1;
  readonly rootKind: 'normal';
  readonly threshold: 2;
  readonly rootEpoch: number;
  readonly memberSetDigest: string;
  readonly rootDigest: string;
  readonly members: readonly TrustedSignerRootMemberV1[];
}

const ROOT_SCHEMA = 'TrustedSignerRootV1' as const;
const ROOT_KIND = 'normal' as const;

function publicKeySpkiDerSha256(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('signer_root_member_key_invalid');
  return createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

function canonicalMemberSet(
  members: readonly { memberId: string; publicKeySpkiDerSha256: string }[],
): string {
  const sorted = [...members]
    .map((member) => ({
      memberId: member.memberId,
      publicKeySpkiDerSha256: member.publicKeySpkiDerSha256,
    }))
    .sort((left, right) =>
      left.memberId < right.memberId ? -1 : left.memberId > right.memberId ? 1 : 0,
    );
  return canonicalJson(sorted);
}

export function buildTrustedSignerRoot(input: {
  members: readonly { memberId: string; publicKeyPem: string }[];
  rootKind: 'normal';
  threshold: 2;
  rootEpoch: number;
}): TrustedSignerRootV1 {
  if (input.members.length !== TRUSTED_SIGNER_ROOT_MEMBER_COUNT) {
    throw new Error('signer_root_member_count_invalid');
  }
  const members = Object.freeze(
    input.members.map((member) =>
      Object.freeze({
        memberId: member.memberId,
        publicKeyPem: member.publicKeyPem,
        publicKeySpkiDerSha256: publicKeySpkiDerSha256(member.publicKeyPem),
      }),
    ),
  );
  if (new Set(members.map((member) => member.memberId)).size !== members.length) {
    throw new Error('signer_root_member_duplicate');
  }
  const memberSetDigest = createHash('sha256')
    .update(canonicalMemberSet(members), 'utf8')
    .digest('hex');
  const rootDigest = createHash('sha256')
    .update(
      canonicalJson({
        schema: ROOT_SCHEMA,
        version: 1,
        rootKind: input.rootKind,
        threshold: input.threshold,
        rootEpoch: input.rootEpoch,
        memberSetDigest,
        members: canonicalMemberSet(members),
      }),
      'utf8',
    )
    .digest('hex');
  return Object.freeze({
    schema: ROOT_SCHEMA,
    version: 1,
    rootKind: input.rootKind,
    threshold: input.threshold,
    rootEpoch: input.rootEpoch,
    memberSetDigest,
    rootDigest,
    members,
  }) as unknown as TrustedSignerRootV1;
}

const NORMAL_ROOT_MEMBER_PEMS = [
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxpSAZQnrFMl7x89kmm6VpcbujvCw5h+GjI/j5H0ZfWw=\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA3Tym6D3F2hXvecKkgxrHqMYweqDFGGovk36eHzmvjwI=\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA94sHiDuckRpNTXDNxTG8YNaG3bLgWd8EGc2R2PsKuT8=\n-----END PUBLIC KEY-----\n',
] as const;

export const TRUSTED_SIGNER_ROOT_MEMBERS: readonly TrustedSignerRootMemberV1[] = Object.freeze(
  NORMAL_ROOT_MEMBER_PEMS.map((publicKeyPem, index) =>
    Object.freeze({
      memberId: `signer-root-member-${index + 1}`,
      publicKeyPem,
      publicKeySpkiDerSha256: publicKeySpkiDerSha256(publicKeyPem),
    }),
  ),
);

export const TRUSTED_SIGNER_ROOT_MEMBER_SET_DIGEST: string = createHash('sha256')
  .update(canonicalMemberSet(TRUSTED_SIGNER_ROOT_MEMBERS), 'utf8')
  .digest('hex');

export const trustedSignerRootV1: TrustedSignerRootV1 = buildTrustedSignerRoot({
  members: TRUSTED_SIGNER_ROOT_MEMBERS,
  rootKind: ROOT_KIND,
  threshold: 2,
  rootEpoch: 1,
});

export const TRUSTED_SIGNER_ROOT_DIGEST: string = trustedSignerRootV1.rootDigest;

// Generation-one bootstrap enrollment subject: the distinct bootstrap discriminator with no floor
// fields (plan "root-enrollment authorization digest").
export interface SignerRootEnrollmentBootstrapSubjectV1 {
  readonly domainTag: 'folklore.signer-root-enrollment-bootstrap.v1';
  readonly version: 1;
  readonly rootEnrollmentPayloadDigest: string;
  readonly keysetGeneration: number;
  readonly keysetDigest: string;
  readonly normalRootDigest: string;
  readonly recoveryRootDigest: string;
  readonly rootEpoch: number;
  readonly memberSetDigest: string;
  readonly environment: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
}

export interface SignerRootEnrollmentFloorBoundSubjectV1 {
  readonly domainTag: 'folklore.signer-root-enrollment-floor-bound.v1';
  readonly version: 1;
  readonly rootEnrollmentPayloadDigest: string;
  readonly enrollmentGeneration: number;
  readonly keysetGeneration: number;
  readonly keysetDigest: string;
  readonly normalRootDigest: string;
  readonly recoveryRootDigest: string;
  readonly rootEpoch: number;
  readonly memberSetDigest: string;
  readonly environment: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
  readonly previousFloorGeneration: number;
  readonly previousFloorDigest: string;
}

export function buildSignerRootEnrollmentBootstrapSubjectV1(
  input: SignerRootEnrollmentBootstrapSubjectV1,
): unknown[] {
  return [
    input.domainTag,
    input.version,
    input.rootEnrollmentPayloadDigest,
    input.keysetGeneration,
    input.keysetDigest,
    input.normalRootDigest,
    input.recoveryRootDigest,
    input.rootEpoch,
    input.memberSetDigest,
    input.environment,
    input.awsAccountId,
    input.awsRegion,
  ];
}

export function buildSignerRootEnrollmentFloorBoundSubjectV1(
  input: SignerRootEnrollmentFloorBoundSubjectV1,
): unknown[] {
  if (!/^[0-9a-f]{64}$/.test(input.previousFloorDigest)) {
    throw new Error('signer_root_previous_floor_digest_invalid');
  }
  return [
    input.domainTag,
    input.version,
    input.rootEnrollmentPayloadDigest,
    input.enrollmentGeneration,
    input.keysetGeneration,
    input.keysetDigest,
    input.normalRootDigest,
    input.recoveryRootDigest,
    input.rootEpoch,
    input.memberSetDigest,
    input.environment,
    input.awsAccountId,
    input.awsRegion,
    input.previousFloorGeneration,
    input.previousFloorDigest,
  ];
}

export type SignerRootEnrollmentSubjectV1 =
  | SignerRootEnrollmentBootstrapSubjectV1
  | SignerRootEnrollmentFloorBoundSubjectV1;

export function canonicalSignerRootEnrollmentSubjectBytes(
  subject: SignerRootEnrollmentSubjectV1,
): Uint8Array {
  if (subject.domainTag === 'folklore.signer-root-enrollment-bootstrap.v1') {
    return canonicalCbor(buildSignerRootEnrollmentBootstrapSubjectV1(subject));
  }
  return canonicalCbor(buildSignerRootEnrollmentFloorBoundSubjectV1(subject));
}

export interface SignerRootEnrollmentAuthorizationPreimageV1 {
  schema: 'SignerRootEnrollmentAuthorizationPreimageV1';
  version: 1;
  authorizationKind: 'normal_root_enrollment';
  authorizationSubjectName:
    | 'SignerRootEnrollmentBootstrapSubjectV1'
    | 'SignerRootEnrollmentFloorBoundSubjectV1';
  authorizationDomainTag: string;
  authorizationSubjectDigest: string;
  rootEnrollmentPayloadDigest: string;
  enrollmentGeneration: number;
  keysetGeneration: number;
  keysetDigest: string;
  signerKmsMetadataReceiptDigests: readonly { purpose: string; digest: string }[];
  normalRootDigest: string;
  recoveryRootDigest: string;
  rootEpoch: number;
  memberSetDigest: string;
  environment: string;
  awsAccountId: string;
  awsRegion: string;
  readerCapabilityContext: Record<string, unknown>;
  previousFloorGeneration?: number;
  previousFloorDigest?: string;
}

export function signerRootEnrollmentAuthorizationDigest(
  preimage: SignerRootEnrollmentAuthorizationPreimageV1,
): string {
  return createHash('sha256').update(canonicalJson(preimage), 'utf8').digest('hex');
}

export interface SignerRootQuorumSignatureV1 {
  readonly memberId: string;
  readonly signature: string;
}

export function verifySignerRootQuorum(input: {
  root: TrustedSignerRootV1;
  domainTag: string;
  subjectBytes: Uint8Array;
  signatures: readonly SignerRootQuorumSignatureV1[];
}): void {
  if (input.root.rootKind !== 'normal' || input.root.threshold !== 2) {
    throw new Error('signer_root_invalid');
  }
  if (input.signatures.length < 2) throw new Error('signer_root_quorum_invalid');
  const memberIds = input.signatures.map((entry) => entry.memberId);
  if (new Set(memberIds).size !== memberIds.length) {
    throw new Error('signer_root_quorum_invalid');
  }
  const message = Buffer.concat([
    Buffer.from(`${input.domainTag}\u0000`, 'utf8'),
    Buffer.from(input.subjectBytes),
  ]);
  let validCount = 0;
  for (const entry of input.signatures) {
    const member = input.root.members.find((candidate) => candidate.memberId === entry.memberId);
    if (!member) throw new Error('signer_root_member_unavailable');
    let publicKey;
    try {
      publicKey = createPublicKey(member.publicKeyPem);
    } catch {
      throw new Error('signer_root_member_key_invalid');
    }
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('signer_root_member_key_invalid');
    }
    const valid = verify(null, message, publicKey, Buffer.from(entry.signature, 'base64'));
    if (!valid) throw new Error('signer_root_signature_invalid');
    validCount += 1;
  }
  if (validCount < input.root.threshold) throw new Error('signer_root_quorum_invalid');
}
