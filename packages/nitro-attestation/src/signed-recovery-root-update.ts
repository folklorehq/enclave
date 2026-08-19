import { createHash } from 'node:crypto';
import { canonicalJson } from '@folklore/contracts';
import { canonicalCbor, digestCanonicalCbor } from './canonical-cbor.js';
import {
  verifyRecoveryRootQuorum,
  type TrustedSignerRecoveryRootV1,
} from './trusted-signer-recovery-root.js';

// SignedRecoveryRootUpdateV1: verified against the OLD independently pinned recovery root using the
// floor-bound discriminator. The previous floor fields must equal the loader's latest committed floor
// snapshot before the update is evaluated (plan "Keyset, roots, recovery installation, and reader
// capability").

const digest64Pattern = /^[0-9a-f]{64}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const ed25519SignaturePattern = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/;

export interface SignedRecoveryRootUpdateV1 {
  readonly schema: 'SignedRecoveryRootUpdateV1';
  readonly version: 1;
  readonly recoveryRootUpdatePayloadDigest: string;
  readonly oldRecoveryRootDigest: string;
  readonly newRecoveryRootDigest: string;
  readonly oldRootEpoch: number;
  readonly newRootEpoch: number;
  readonly verifierUpdateDigest: string;
  readonly requiredReaderSetDigest: string;
  readonly environment: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
  readonly previousFloorGeneration: number;
  readonly previousFloorDigest: string;
  readonly subjectDigest: string;
  readonly signatures: readonly {
    readonly memberId: string;
    readonly signature: string;
  }[];
}

export const signedRecoveryRootUpdateV1Schema = {
  parse(input: unknown): SignedRecoveryRootUpdateV1 {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    const value = input as Record<string, unknown>;
    if (value['schema'] !== 'SignedRecoveryRootUpdateV1' || value['version'] !== 1) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    const strings: Array<[string, RegExp]> = [
      ['recoveryRootUpdatePayloadDigest', digest64Pattern],
      ['oldRecoveryRootDigest', digest64Pattern],
      ['newRecoveryRootDigest', digest64Pattern],
      ['verifierUpdateDigest', digest64Pattern],
      ['requiredReaderSetDigest', digest64Pattern],
      ['previousFloorDigest', digest64Pattern],
      ['subjectDigest', digest64Pattern],
    ];
    for (const [field, pattern] of strings) {
      if (typeof value[field] !== 'string' || !pattern.test(value[field] as string)) {
        throw new Error('signed_recovery_root_update_invalid');
      }
    }
    if (
      typeof value['environment'] !== 'string' ||
      value['environment'].length < 1 ||
      value['environment'].length > 128 ||
      typeof value['awsAccountId'] !== 'string' ||
      !/^\d{12}$/.test(value['awsAccountId'] as string) ||
      typeof value['awsRegion'] !== 'string' ||
      value['awsRegion'].length < 9 ||
      value['awsRegion'].length > 32
    ) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    for (const field of ['oldRootEpoch', 'newRootEpoch', 'previousFloorGeneration']) {
      const numberValue = value[field];
      if (
        typeof numberValue !== 'number' ||
        !Number.isSafeInteger(numberValue) ||
        numberValue < 1
      ) {
        throw new Error('signed_recovery_root_update_invalid');
      }
    }
    if (!Array.isArray(value['signatures']) || value['signatures'].length !== 3) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    const signatures = (value['signatures'] as unknown[]).map((entry) => {
      if (typeof entry !== 'object' || entry === null) {
        throw new Error('signed_recovery_root_update_invalid');
      }
      const record = entry as Record<string, unknown>;
      if (
        typeof record['memberId'] !== 'string' ||
        !identifierPattern.test(record['memberId']) ||
        typeof record['signature'] !== 'string' ||
        !ed25519SignaturePattern.test(record['signature'])
      ) {
        throw new Error('signed_recovery_root_update_invalid');
      }
      return { memberId: record['memberId'], signature: record['signature'] };
    });
    const members = signatures.map((entry) => entry.memberId);
    const sorted = [...members].sort();
    if (members.some((member, index) => member !== sorted[index])) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    if (new Set(members).size !== members.length) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    const parsed: SignedRecoveryRootUpdateV1 = {
      schema: 'SignedRecoveryRootUpdateV1',
      version: 1,
      recoveryRootUpdatePayloadDigest: value['recoveryRootUpdatePayloadDigest'] as string,
      oldRecoveryRootDigest: value['oldRecoveryRootDigest'] as string,
      newRecoveryRootDigest: value['newRecoveryRootDigest'] as string,
      oldRootEpoch: value['oldRootEpoch'] as number,
      newRootEpoch: value['newRootEpoch'] as number,
      verifierUpdateDigest: value['verifierUpdateDigest'] as string,
      requiredReaderSetDigest: value['requiredReaderSetDigest'] as string,
      environment: value['environment'] as string,
      awsAccountId: value['awsAccountId'] as string,
      awsRegion: value['awsRegion'] as string,
      previousFloorGeneration: value['previousFloorGeneration'] as number,
      previousFloorDigest: value['previousFloorDigest'] as string,
      subjectDigest: value['subjectDigest'] as string,
      signatures,
    };
    if (parsed.newRootEpoch <= parsed.oldRootEpoch) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    if (parsed.newRecoveryRootDigest === parsed.oldRecoveryRootDigest) {
      throw new Error('signed_recovery_root_update_invalid');
    }
    return Object.freeze(parsed) as unknown as SignedRecoveryRootUpdateV1;
  },
  safeParse(input: unknown): { success: boolean; data?: SignedRecoveryRootUpdateV1 } {
    try {
      return { success: true, data: this.parse(input) };
    } catch {
      return { success: false };
    }
  },
};

export interface RecoveryRootUpdateFloorBoundSubjectV1 {
  readonly domainTag: 'folklore.recovery-root-update-floor-bound.v1';
  readonly version: 1;
  readonly recoveryRootUpdatePayloadDigest: string;
  readonly oldRecoveryRootDigest: string;
  readonly newRecoveryRootDigest: string;
  readonly oldRootEpoch: number;
  readonly newRootEpoch: number;
  readonly verifierUpdateDigest: string;
  readonly environment: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
  readonly previousFloorGeneration: number;
  readonly previousFloorDigest: string;
}

export function buildRecoveryRootUpdateFloorBoundSubjectV1(
  input: RecoveryRootUpdateFloorBoundSubjectV1,
): unknown[] {
  if (!/^[0-9a-f]{64}$/.test(input.previousFloorDigest)) {
    throw new Error('recovery_root_previous_floor_digest_invalid');
  }
  return [
    input.domainTag,
    input.version,
    input.recoveryRootUpdatePayloadDigest,
    input.oldRecoveryRootDigest,
    input.newRecoveryRootDigest,
    input.oldRootEpoch,
    input.newRootEpoch,
    input.verifierUpdateDigest,
    input.environment,
    input.awsAccountId,
    input.awsRegion,
    input.previousFloorGeneration,
    input.previousFloorDigest,
  ];
}

export function canonicalRecoveryRootUpdateSubjectBytes(
  input: RecoveryRootUpdateFloorBoundSubjectV1,
): Uint8Array {
  return canonicalCbor(buildRecoveryRootUpdateFloorBoundSubjectV1(input));
}

export interface RecoveryRootUpdateAuthorizationPreimageV1 {
  schema: 'RecoveryRootUpdateAuthorizationPreimageV1';
  version: 1;
  authorizationKind: 'recovery_root_update';
  authorizationSubjectName: 'RecoveryRootUpdateFloorBoundSubjectV1';
  authorizationDomainTag: 'folklore.recovery-root-update-floor-bound.v1';
  authorizationSubjectDigest: string;
  recoveryRootUpdatePayloadDigest: string;
  oldRecoveryRootDigest: string;
  newRecoveryRootDigest: string;
  oldRootEpoch: number;
  newRootEpoch: number;
  verifierUpdateDigest: string;
  requiredReaderSetDigest: string;
  readerCapabilityContext: Record<string, unknown>;
  environment: string;
  awsAccountId: string;
  awsRegion: string;
  previousFloorGeneration: number;
  previousFloorDigest: string;
}

export function recoveryRootUpdateAuthorizationDigest(
  preimage: RecoveryRootUpdateAuthorizationPreimageV1,
): string {
  return createHash('sha256').update(canonicalJson(preimage), 'utf8').digest('hex');
}

export function verifySignedRecoveryRootUpdate(input: {
  update: SignedRecoveryRootUpdateV1;
  oldRoot: TrustedSignerRecoveryRootV1;
  floor: { floorGeneration: number; floorDigest: string };
}): void {
  let update: SignedRecoveryRootUpdateV1;
  try {
    update = signedRecoveryRootUpdateV1Schema.parse(input.update);
  } catch (error) {
    const signatures = (input.update as { signatures?: unknown }).signatures;
    if (Array.isArray(signatures) && signatures.length !== 3) {
      throw new Error('recovery_root_quorum_invalid');
    }
    throw error;
  }
  if (
    update.previousFloorGeneration !== input.floor.floorGeneration ||
    update.previousFloorDigest !== input.floor.floorDigest
  ) {
    throw new Error('recovery_root_previous_floor_mismatch');
  }
  if (update.oldRecoveryRootDigest !== input.oldRoot.rootDigest) {
    throw new Error('recovery_root_old_root_mismatch');
  }
  // A verifier update digest that aliases an already-bound digest is a reuse/rollback attempt.
  if (
    update.verifierUpdateDigest === update.previousFloorDigest ||
    update.verifierUpdateDigest === update.oldRecoveryRootDigest ||
    update.verifierUpdateDigest === update.newRecoveryRootDigest
  ) {
    throw new Error('recovery_root_verifier_update_digest_reused');
  }
  const subject: RecoveryRootUpdateFloorBoundSubjectV1 = {
    domainTag: 'folklore.recovery-root-update-floor-bound.v1',
    version: 1,
    recoveryRootUpdatePayloadDigest: update.recoveryRootUpdatePayloadDigest,
    oldRecoveryRootDigest: update.oldRecoveryRootDigest,
    newRecoveryRootDigest: update.newRecoveryRootDigest,
    oldRootEpoch: update.oldRootEpoch,
    newRootEpoch: update.newRootEpoch,
    verifierUpdateDigest: update.verifierUpdateDigest,
    environment: update.environment,
    awsAccountId: update.awsAccountId,
    awsRegion: update.awsRegion,
    previousFloorGeneration: update.previousFloorGeneration,
    previousFloorDigest: update.previousFloorDigest,
  };
  const bytes = canonicalRecoveryRootUpdateSubjectBytes(subject);
  if (digestCanonicalCbor(bytes) !== update.subjectDigest) {
    throw new Error('recovery_root_subject_digest_mismatch');
  }
  verifyRecoveryRootQuorum({
    root: input.oldRoot,
    domainTag: subject.domainTag,
    subjectBytes: bytes,
    signatures: update.signatures,
  });
}
