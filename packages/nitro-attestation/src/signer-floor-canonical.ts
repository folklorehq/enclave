import { createHash } from 'node:crypto';

import {
  canonicalJson,
  signerFloorBootstrapSubjectArrayV1,
  signerFloorCommitSubjectArrayV1,
  type SignerFloorBootstrapSubjectInputV1,
  type SignerFloorCommitSubjectV1,
} from '@folklore/contracts';

import { canonicalCbor } from './canonical-cbor.js';

export function canonicalSignerFloorBootstrapSubjectBytes(
  input: SignerFloorBootstrapSubjectInputV1,
): Uint8Array {
  return canonicalCbor(
    signerFloorBootstrapSubjectArrayV1({
      environment: input.environment,
      awsAccountId: input.awsAccountId,
      awsRegion: input.awsRegion,
      normalRootDigest: input.normalRootDigest,
      recoveryRootDigest: input.recoveryRootDigest,
      rootEpoch: input.rootEpoch,
      ssmParameterPrefix: input.ssmParameterPrefix,
      bucketIdentityDigest: createHash('sha256')
        .update(canonicalJson(input.bucketIdentity), 'utf8')
        .digest('hex'),
    }),
  );
}

export function canonicalSignerFloorCommitSubjectBytes(
  input: SignerFloorCommitSubjectV1,
): Uint8Array {
  return canonicalCbor(signerFloorCommitSubjectArrayV1(input));
}
