import { createHash } from 'node:crypto';

import { encode, rfc8949EncodeOptions } from 'cborg';
import {
  ASSIGNMENT_MANIFEST_V3_DOMAIN,
  ONLINE_SIGNER_PURPOSE_DOMAINS,
  ONLINE_SIGNER_PURPOSE_VALUES,
  assignmentManifestV3PayloadSchema,
  buildSignerPurposeSignatureMessage,
  canonicalJson,
  custodyCanonicalVectorSetV1Schema,
  type CustodyCanonicalVectorSetV1,
  type CustodyCanonicalVectorRecordV1,
  type OnlineSignerPurpose,
} from '@folklore/contracts';
import { canonicalJsonDigest, encodeAssignmentManifestSubjectV3 } from './canonical-cbor.js';

const ENVIRONMENT = 'test';
const AWS_ACCOUNT_ID = '111122223333';
const AWS_REGION = 'us-east-1';
const DIGEST_A = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const DIGEST_B = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
const DIGEST_C = '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f';
const SUBJECT_DIGEST_BYTES = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index));

export const CUSTODY_CANONICAL_VECTOR_SOURCE_PATH =
  'packages/nitro-attestation/src/custody-canonical-vectors.ts';
export const H0_CUSTODY_VECTOR_NAMES = [
  'floor-generation-1',
  'floor-generation-2',
  'purpose-signature-message',
  'recovery-root-update',
] as const;
export const H2_CUSTODY_VECTOR_NAMES = [
  'assignment-manifest-v3-payload',
  ...H0_CUSTODY_VECTOR_NAMES,
] as const;

function sha256Hex(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString('hex');
}

function canonicalCbor(value: unknown): Uint8Array {
  return encode(value, rfc8949EncodeOptions);
}

function negativeCaseDigest(vectorName: string, negativeCase: string): string {
  return sha256Hex(utf8(canonicalJson({ vectorName, negativeCase })));
}

function negativeCaseDigests(vectorName: string, cases: readonly string[]): string[] {
  return cases.map((negativeCase) => negativeCaseDigest(vectorName, negativeCase)).sort();
}

function signatureMessage(domainTag: string, subjectBytes: Uint8Array): Uint8Array {
  const head = utf8(`${domainTag}\u0000`);
  const message = new Uint8Array(head.length + subjectBytes.length);
  message.set(head, 0);
  message.set(subjectBytes, head.length);
  return message;
}

export interface OnlinePurposeSignatureMessageVectorV1 {
  readonly purpose: OnlineSignerPurpose;
  readonly domain: string;
  readonly messageHex: string;
  readonly messageSha256: string;
}

export function onlinePurposeSignatureMessages(
  subjectDigestBytes: Uint8Array,
): readonly OnlinePurposeSignatureMessageVectorV1[] {
  return ONLINE_SIGNER_PURPOSE_VALUES.map((purpose) => {
    const message = buildSignerPurposeSignatureMessage(
      purpose,
      ONLINE_SIGNER_PURPOSE_DOMAINS[purpose],
      subjectDigestBytes,
    );
    return {
      purpose,
      domain: ONLINE_SIGNER_PURPOSE_DOMAINS[purpose],
      messageHex: toHex(message),
      messageSha256: sha256Hex(message),
    };
  });
}

const sortedReceiptDigests = [
  { purpose: 'assignment_manifest', digest: DIGEST_C },
  { purpose: 'boot_manifest', digest: DIGEST_A },
  { purpose: 'dormant_carrier', digest: DIGEST_B },
] as const;

function floorGenerationOneVector(): CustodyCanonicalVectorRecordV1 {
  const domainTag = 'folklore.signer-root-enrollment-bootstrap.v1';
  const typedValue = [
    domainTag,
    1,
    DIGEST_A,
    1,
    DIGEST_B,
    DIGEST_C,
    DIGEST_A,
    1,
    DIGEST_B,
    ENVIRONMENT,
    AWS_ACCOUNT_ID,
    AWS_REGION,
  ];
  const subjectBytes = canonicalCbor(typedValue);
  const preimage = {
    schema: 'SignerRootEnrollmentAuthorizationPreimageV1',
    version: 1,
    authorizationKind: 'normal_root_enrollment',
    authorizationSubjectName: 'SignerRootEnrollmentBootstrapSubjectV1',
    authorizationDomainTag: domainTag,
    authorizationSubjectDigest: sha256Hex(subjectBytes),
    rootEnrollmentPayloadDigest: DIGEST_A,
    enrollmentGeneration: 1,
    keysetGeneration: 1,
    keysetDigest: DIGEST_B,
    signerKmsMetadataReceiptDigests: sortedReceiptDigests,
    normalRootDigest: DIGEST_C,
    recoveryRootDigest: DIGEST_A,
    rootEpoch: 1,
    memberSetDigest: DIGEST_B,
    environment: ENVIRONMENT,
    awsAccountId: AWS_ACCOUNT_ID,
    awsRegion: AWS_REGION,
    readerCapabilityContext: {
      kind: 'bootstrap',
      recoveryRootDigest: DIGEST_A,
      readerCapabilityDigest: null,
    },
  };
  const message = signatureMessage(domainTag, subjectBytes);
  return {
    vectorName: 'floor-generation-1',
    domainTag,
    typedSubjectName: 'SignerRootEnrollmentBootstrapSubjectV1',
    typedSubjectValueDiagnostic: canonicalJson(typedValue),
    canonicalSubjectBytesHex: toHex(subjectBytes),
    canonicalSubjectBytesSha256: sha256Hex(subjectBytes),
    authorizationPreimageCanonicalJsonSha256: sha256Hex(utf8(canonicalJson(preimage))),
    signatureMessageHex: toHex(message),
    signatureMessageSha256: sha256Hex(message),
    expectedEnvelopeDigest: null,
    negativeCaseDigests: negativeCaseDigests('floor-generation-1', [
      'bootstrap-subject-with-floor-digest',
      'bootstrap-subject-with-previous-floor-digest',
      'wrong-domain-tag',
      'reordered-subject-fields',
      'omitted-authorization-kind',
      'wrong-authorization-digest',
      'cross-kind-recovery-substitution',
    ]),
  };
}

function floorGenerationTwoVector(): CustodyCanonicalVectorRecordV1 {
  const domainTag = 'folklore.signer-root-enrollment-floor-bound.v1';
  const typedValue = [
    domainTag,
    1,
    DIGEST_A,
    2,
    2,
    DIGEST_C,
    DIGEST_A,
    DIGEST_B,
    1,
    DIGEST_C,
    ENVIRONMENT,
    AWS_ACCOUNT_ID,
    AWS_REGION,
    1,
    DIGEST_B,
  ];
  const subjectBytes = canonicalCbor(typedValue);
  const preimage = {
    schema: 'SignerRootEnrollmentAuthorizationPreimageV1',
    version: 1,
    authorizationKind: 'normal_root_enrollment',
    authorizationSubjectName: 'SignerRootEnrollmentFloorBoundSubjectV1',
    authorizationDomainTag: domainTag,
    authorizationSubjectDigest: sha256Hex(subjectBytes),
    rootEnrollmentPayloadDigest: DIGEST_A,
    enrollmentGeneration: 2,
    keysetGeneration: 2,
    keysetDigest: DIGEST_C,
    signerKmsMetadataReceiptDigests: sortedReceiptDigests,
    normalRootDigest: DIGEST_A,
    recoveryRootDigest: DIGEST_B,
    rootEpoch: 1,
    memberSetDigest: DIGEST_C,
    environment: ENVIRONMENT,
    awsAccountId: AWS_ACCOUNT_ID,
    awsRegion: AWS_REGION,
    readerCapabilityContext: {
      kind: 'prior_floor',
      priorFloorDigest: DIGEST_B,
      recoveryRootDigest: DIGEST_A,
      readerCapabilityDigest: DIGEST_B,
    },
    previousFloorGeneration: 1,
    previousFloorDigest: DIGEST_B,
  };
  const message = signatureMessage(domainTag, subjectBytes);
  return {
    vectorName: 'floor-generation-2',
    domainTag,
    typedSubjectName: 'SignerRootEnrollmentFloorBoundSubjectV1',
    typedSubjectValueDiagnostic: canonicalJson(typedValue),
    canonicalSubjectBytesHex: toHex(subjectBytes),
    canonicalSubjectBytesSha256: sha256Hex(subjectBytes),
    authorizationPreimageCanonicalJsonSha256: sha256Hex(utf8(canonicalJson(preimage))),
    signatureMessageHex: toHex(message),
    signatureMessageSha256: sha256Hex(message),
    expectedEnvelopeDigest: null,
    negativeCaseDigests: negativeCaseDigests('floor-generation-2', [
      'previous-floor-digest-null',
      'previous-floor-generations-mismatch',
      'stale-previous-floor-digest',
      'candidate-floor-digest-as-previous',
      'bootstrap-subject-substituted',
      'recovery-kind-substituted',
    ]),
  };
}

function recoveryRootUpdateVector(): CustodyCanonicalVectorRecordV1 {
  const domainTag = 'folklore.recovery-root-update-floor-bound.v1';
  const typedValue = [
    domainTag,
    1,
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    1,
    2,
    DIGEST_A,
    ENVIRONMENT,
    AWS_ACCOUNT_ID,
    AWS_REGION,
    2,
    DIGEST_C,
  ];
  const subjectBytes = canonicalCbor(typedValue);
  const preimage = {
    schema: 'RecoveryRootUpdateAuthorizationPreimageV1',
    version: 1,
    authorizationKind: 'recovery_root_update',
    authorizationSubjectName: 'RecoveryRootUpdateFloorBoundSubjectV1',
    authorizationDomainTag: domainTag,
    authorizationSubjectDigest: sha256Hex(subjectBytes),
    recoveryRootUpdatePayloadDigest: DIGEST_A,
    oldRecoveryRootDigest: DIGEST_B,
    newRecoveryRootDigest: DIGEST_C,
    oldRootEpoch: 1,
    newRootEpoch: 2,
    verifierUpdateDigest: DIGEST_A,
    requiredReaderSetDigest: DIGEST_B,
    readerCapabilityContext: {
      kind: 'prior_floor',
      priorFloorDigest: DIGEST_C,
      recoveryRootDigest: DIGEST_B,
      readerCapabilityDigest: DIGEST_A,
    },
    environment: ENVIRONMENT,
    awsAccountId: AWS_ACCOUNT_ID,
    awsRegion: AWS_REGION,
    previousFloorGeneration: 2,
    previousFloorDigest: DIGEST_C,
  };
  const message = signatureMessage(domainTag, subjectBytes);
  return {
    vectorName: 'recovery-root-update',
    domainTag,
    typedSubjectName: 'RecoveryRootUpdateFloorBoundSubjectV1',
    typedSubjectValueDiagnostic: canonicalJson(typedValue),
    canonicalSubjectBytesHex: toHex(subjectBytes),
    canonicalSubjectBytesSha256: sha256Hex(subjectBytes),
    authorizationPreimageCanonicalJsonSha256: sha256Hex(utf8(canonicalJson(preimage))),
    signatureMessageHex: toHex(message),
    signatureMessageSha256: sha256Hex(message),
    expectedEnvelopeDigest: null,
    negativeCaseDigests: negativeCaseDigests('recovery-root-update', [
      'signed-by-new-root',
      'omitted-previous-floor-fields',
      'future-floor-binding',
      'prior-verifier-digest-reuse',
      'normal-enrollment-substitution',
      'forked-floor-chain',
    ]),
  };
}

function purposeSignatureMessageVector(): CustodyCanonicalVectorRecordV1 {
  const domainTag = 'folklore.signer-purpose.v1';
  const messages = onlinePurposeSignatureMessages(SUBJECT_DIGEST_BYTES);
  const bootMessage = messages.find((message) => message.purpose === 'boot-manifest');
  if (bootMessage === undefined) throw new Error('boot_manifest_message_unavailable');
  return {
    vectorName: 'purpose-signature-message',
    domainTag,
    typedSubjectName: 'PurposeSignatureMessage',
    typedSubjectValueDiagnostic: canonicalJson({
      subjectDigestBytes: toHex(SUBJECT_DIGEST_BYTES),
      purposes: messages.map((message) => message.purpose),
    }),
    canonicalSubjectBytesHex: toHex(SUBJECT_DIGEST_BYTES),
    canonicalSubjectBytesSha256: sha256Hex(SUBJECT_DIGEST_BYTES),
    authorizationPreimageCanonicalJsonSha256: null,
    signatureMessageHex: bootMessage.messageHex,
    signatureMessageSha256: bootMessage.messageSha256,
    expectedEnvelopeDigest: null,
    negativeCaseDigests: negativeCaseDigests('purpose-signature-message', [
      'wrong-purpose-dormant-boot-carrier-message',
      'wrong-purpose-assignment-manifest-message',
      'wrong-domain-assignment-manifest-message',
      'wrong-subject-digest-bytes',
      'missing-nul-separator',
      'reordered-message-parts',
      'message-type-digest',
      'ed25519-ph-sha-512',
    ]),
  };
}

const H0_VECTORS: readonly CustodyCanonicalVectorRecordV1[] = [
  floorGenerationOneVector(),
  floorGenerationTwoVector(),
  purposeSignatureMessageVector(),
  recoveryRootUpdateVector(),
].sort((left, right) => left.vectorName.localeCompare(right.vectorName));

function assignmentManifestV3PayloadVector(): CustodyCanonicalVectorRecordV1 {
  const domainTag = ASSIGNMENT_MANIFEST_V3_DOMAIN;
  const generation = 1;
  const orgId = 'org-custody';
  const deploymentId = 'deployment-custody';
  const poolId = 'pool-custody';
  // The v3 payload is content-free by schema: tenant IDs, KMS/queue/bucket names, and scope are
  // structural identifiers, and no signer-owned field (digest, signature, key, purpose) is allowed.
  const payload = assignmentManifestV3PayloadSchema.parse({
    schema: 'AssignmentManifestV3Payload',
    version: 3,
    poolId,
    assignments: [
      {
        tenantId: 'tenant-custody',
        deploymentId,
        kmsKeyId: 'cmk-custody',
        storageKeyId: 'storage-custody',
        activeStorageKeyVersion: 1,
        storageKeyHistory: [{ version: 1, storageKeyId: 'storage-custody' }],
        queueUrl: `https://sqs.${AWS_REGION}.amazonaws.com/${AWS_ACCOUNT_ID}/custody-queue`,
        sealedBlobBucket: 'sealed-blob-custody',
        rawPayloadsBucket: 'raw-payloads-custody',
        processedBucket: 'processed-custody',
        recoveryPubkey: '',
      },
    ],
    generation,
    environment: ENVIRONMENT,
    awsAccountId: AWS_ACCOUNT_ID,
    awsRegion: AWS_REGION,
    orgId,
    deploymentId,
  });
  const typedValue = [
    domainTag,
    3,
    canonicalJsonDigest(payload),
    generation,
    orgId,
    deploymentId,
    poolId,
    ENVIRONMENT,
    AWS_ACCOUNT_ID,
    AWS_REGION,
  ];
  // The v3 signer signs the purpose message over the subject digest, not the subject bytes.
  const subjectBytes = encodeAssignmentManifestSubjectV3({ payload });
  const subjectDigest = sha256Hex(subjectBytes);
  const message = buildSignerPurposeSignatureMessage(
    'assignment-manifest',
    ONLINE_SIGNER_PURPOSE_DOMAINS['assignment-manifest'],
    Buffer.from(subjectDigest, 'hex'),
  );
  return {
    vectorName: 'assignment-manifest-v3-payload',
    domainTag,
    typedSubjectName: 'AssignmentManifestSubjectV3',
    typedSubjectValueDiagnostic: canonicalJson(typedValue),
    canonicalSubjectBytesHex: toHex(subjectBytes),
    canonicalSubjectBytesSha256: subjectDigest,
    authorizationPreimageCanonicalJsonSha256: null,
    signatureMessageHex: toHex(message),
    signatureMessageSha256: sha256Hex(message),
    expectedEnvelopeDigest: null,
    negativeCaseDigests: negativeCaseDigests('assignment-manifest-v3-payload', [
      'signer-owned-digest-field-in-payload',
      'signer-owned-signature-field-in-payload',
      'wrong-domain-tag',
      'reordered-subject-fields',
      'wrong-payload-digest',
      'wrong-assignment-generation',
      'wrong-org-id',
      'wrong-deployment-id',
      'wrong-pool-id',
      'wrong-environment',
      'wrong-aws-account-id',
      'wrong-aws-region',
      'subject-digest-over-envelope',
      'double-encoded-subject-bytes',
      'wrong-purpose-assignment-message',
    ]),
  };
}

const H2_VECTORS: readonly CustodyCanonicalVectorRecordV1[] = [
  ...H0_VECTORS,
  assignmentManifestV3PayloadVector(),
].sort((left, right) => left.vectorName.localeCompare(right.vectorName));

export function buildCustodyCanonicalVectorSetV1(input: {
  readonly stage: 'H0' | 'H2';
  readonly sourceLineageDigest: string;
  readonly planSha256: string;
  readonly generatorSourceDigest: string;
  readonly vectorSourceDigest: string;
  readonly generatedAtCommandDigest: string;
}): CustodyCanonicalVectorSetV1 {
  const vectorSet = {
    schema: 'CustodyCanonicalVectorSetV1',
    version: 1,
    stage: input.stage,
    sourceLineageDigest: input.sourceLineageDigest,
    planSha256: input.planSha256,
    generatorSourceDigest: input.generatorSourceDigest,
    vectorSourceDigest: input.vectorSourceDigest,
    generatedAtCommandDigest: input.generatedAtCommandDigest,
    vectors: input.stage === 'H2' ? H2_VECTORS : H0_VECTORS,
    noCustomerContent: true,
  } as const;
  return custodyCanonicalVectorSetV1Schema.parse(vectorSet);
}

export function canonicalCustodyVectorSetDigest(set: CustodyCanonicalVectorSetV1): string {
  const parsed = custodyCanonicalVectorSetV1Schema.parse(set);
  return sha256Hex(utf8(canonicalJson(parsed)));
}
