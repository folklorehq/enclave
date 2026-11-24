import { createHash } from 'node:crypto';
import { canonicalJson } from '@folklore/contracts';
import { canonicalCbor } from './canonical-cbor.js';

// The update subject is verified against the OLD independently pinned recovery root using the
// floor-bound discriminator; the previous floor fields must equal the loader's latest committed
// floor snapshot.

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
