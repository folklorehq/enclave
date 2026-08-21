import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalJson } from '@folklore/contracts'; // The independently pinned recovery signer root (plan "Keyset, roots, recovery installation, and
// reader capability"): exactly five active Ed25519 members, threshold 3-of-5. It is NOT a field
// inside the normal root or any incoming keyset. The pinned artifact carries public material only;
// tests build their own roots with fresh keys via `buildTrustedSignerRecoveryRoot`.

export const TRUSTED_SIGNER_RECOVERY_ROOT_MEMBER_COUNT = 5 as const;
export const TRUSTED_SIGNER_RECOVERY_ROOT_THRESHOLD = 3 as const;

export interface TrustedSignerRecoveryRootMemberV1 {
  readonly memberId: string;
  readonly publicKeyPem: string;
  readonly publicKeySpkiDerSha256: string;
}

export interface TrustedSignerRecoveryRootV1 {
  readonly schema: 'TrustedSignerRecoveryRootV1';
  readonly version: 1;
  readonly rootKind: 'recovery';
  readonly threshold: 3;
  readonly rootEpoch: number;
  readonly memberSetDigest: string;
  readonly rootDigest: string;
  readonly members: readonly TrustedSignerRecoveryRootMemberV1[];
}

const ROOT_SCHEMA = 'TrustedSignerRecoveryRootV1' as const;
const ROOT_KIND = 'recovery' as const;

function publicKeySpkiDerSha256(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('recovery_root_member_key_invalid');
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

export function buildTrustedSignerRecoveryRoot(input: {
  members: readonly { memberId: string; publicKeyPem: string }[];
  rootEpoch: number;
}): TrustedSignerRecoveryRootV1 {
  if (input.members.length !== TRUSTED_SIGNER_RECOVERY_ROOT_MEMBER_COUNT) {
    throw new Error('recovery_root_member_count_invalid');
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
    throw new Error('recovery_root_member_duplicate');
  }
  const memberSetDigest = createHash('sha256')
    .update(canonicalMemberSet(members), 'utf8')
    .digest('hex');
  const rootDigest = createHash('sha256')
    .update(
      canonicalJson({
        schema: ROOT_SCHEMA,
        version: 1,
        rootKind: ROOT_KIND,
        threshold: 3,
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
    rootKind: ROOT_KIND,
    threshold: 3,
    rootEpoch: input.rootEpoch,
    memberSetDigest,
    rootDigest,
    members,
  }) as unknown as TrustedSignerRecoveryRootV1;
}

const RECOVERY_ROOT_MEMBER_PEMS = [
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA5nyAa8SFLOnyyQ8+y16p5Dwg4plMTFoQYf8OtpOjTd0=\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPXM8H5W8ilDG5mTW3L6HvGO52X49O5T8cAYFDAqgilQ=\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHQv7cRFCv7MOnXX7dFgOJMBn9hBP9TDOz462pcc45XQ=\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAW2RKyGGSF7ngyYk+XnCPgthLXGFRz0K9dYRCTTroWow=\n-----END PUBLIC KEY-----\n',
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAMASYV+nldc3Wlj0HzysjourFaHUR9/IEQdqo7MSCg0Q=\n-----END PUBLIC KEY-----\n',
] as const;

export const TRUSTED_SIGNER_RECOVERY_ROOT_MEMBERS: readonly TrustedSignerRecoveryRootMemberV1[] =
  Object.freeze(
    RECOVERY_ROOT_MEMBER_PEMS.map((publicKeyPem, index) =>
      Object.freeze({
        memberId: `signer-recovery-root-member-${index + 1}`,
        publicKeyPem,
        publicKeySpkiDerSha256: publicKeySpkiDerSha256(publicKeyPem),
      }),
    ),
  );

export const TRUSTED_SIGNER_RECOVERY_ROOT_MEMBER_SET_DIGEST: string = createHash('sha256')
  .update(canonicalMemberSet(TRUSTED_SIGNER_RECOVERY_ROOT_MEMBERS), 'utf8')
  .digest('hex');

export const trustedSignerRecoveryRootV1: TrustedSignerRecoveryRootV1 =
  buildTrustedSignerRecoveryRoot({
    members: TRUSTED_SIGNER_RECOVERY_ROOT_MEMBERS,
    rootEpoch: 1,
  });

export const TRUSTED_SIGNER_RECOVERY_ROOT_DIGEST: string = trustedSignerRecoveryRootV1.rootDigest;

export interface RecoveryRootQuorumSignatureV1 {
  readonly memberId: string;
  readonly signature: string;
}

export function verifyRecoveryRootQuorum(input: {
  root: TrustedSignerRecoveryRootV1;
  domainTag: string;
  subjectBytes: Uint8Array;
  signatures: readonly RecoveryRootQuorumSignatureV1[];
}): void {
  if (input.root.rootKind !== 'recovery' || input.root.threshold !== 3) {
    throw new Error('recovery_root_invalid');
  }
  if (input.signatures.length < 3) throw new Error('recovery_root_quorum_invalid');
  const memberIds = input.signatures.map((entry) => entry.memberId);
  if (new Set(memberIds).size !== memberIds.length) {
    throw new Error('recovery_root_quorum_invalid');
  }
  const message = Buffer.concat([
    Buffer.from(`${input.domainTag}\u0000`, 'utf8'),
    Buffer.from(input.subjectBytes),
  ]);
  let validCount = 0;
  for (const entry of input.signatures) {
    const member = input.root.members.find((candidate) => candidate.memberId === entry.memberId);
    if (!member) throw new Error('recovery_root_member_unavailable');
    let publicKey;
    try {
      publicKey = createPublicKey(member.publicKeyPem);
    } catch {
      throw new Error('recovery_root_member_key_invalid');
    }
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('recovery_root_member_key_invalid');
    }
    const valid = verify(null, message, publicKey, Buffer.from(entry.signature, 'base64'));
    if (!valid) throw new Error('recovery_root_signature_invalid');
    validCount += 1;
  }
  if (validCount < input.root.threshold) throw new Error('recovery_root_quorum_invalid');
}
