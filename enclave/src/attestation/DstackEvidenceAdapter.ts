import { createHash } from 'node:crypto';
import { digest64Schema, type Digest64 } from '@folklore/contracts';
import { z } from 'zod';
import {
  digestDstackNativeEvidenceV1,
  type DstackNativeEvidenceV1,
} from '@folklore/nitro-attestation';
import type {
  DstackNativeExpectedEvidenceV1,
  DstackNativeVerificationInputV1,
  DstackNativeVerificationResultV1,
  DstackNativeVerifierPort,
} from './DstackNativeVerifier.js';

const EVIDENCE_MAX_BYTES = 1_048_576;
const WIRE_MAX_BYTES = 1_048_576;
const RTMR_PATTERN = /^[0-9a-f]{96}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/+-]*$/;
const EXPECTED_TCB_STATUS = 'UpToDate';
const TEE_VARIANTS = [
  'dstack-amd-sev-snp',
  'dstack-aws-nitro-tpm',
  'dstack-gcp-tdx',
  'dstack-nitro-enclave',
  'dstack-tdx',
] as const;

const digestArraySchema = z
  .array(digest64Schema)
  .max(64)
  .superRefine((values, context) => {
    if (values.some((value, index) => value < (values[index - 1] ?? value))) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'digests must be sorted' });
    }
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'digests must be unique' });
    }
  });
const upstreamAppInfoSchema = z
  .object({
    appIdDigest: digest64Schema,
    composeHashDigest: digest64Schema,
    instanceIdDigest: digest64Schema,
    deviceIdDigest: digest64Schema,
    mrSystemDigest: digest64Schema,
    mrAggregatedDigest: digest64Schema,
    osImageHashDigest: digest64Schema,
    keyProviderInfoDigest: digest64Schema,
  })
  .strict();
const upstreamEvidenceSchema = z
  .object({
    quoteVerified: z.boolean(),
    eventLogVerified: z.boolean(),
    osImageHashVerified: z.boolean(),
    acpiTablesVerified: z.boolean(),
    teeVariant: z.string().min(1).max(64).regex(IDENTIFIER_PATTERN),
    reportData: z.string().regex(/^[0-9a-f]{128}$/),
    tcbStatus: z.string().min(1).max(64).regex(IDENTIFIER_PATTERN),
    advisoryIds: z.array(z.string().min(1).max(128).regex(IDENTIFIER_PATTERN)).max(64),
    appInfo: upstreamAppInfoSchema,
  })
  .strict();
const expectedEvidenceSchema = z
  .object({
    rtmr: z.string().regex(RTMR_PATTERN),
    runtimeIdentityDigest: digest64Schema,
    workloadArtifactDigest: digest64Schema,
    routeIdentityDigest: digest64Schema,
    tcbStatus: z.string().min(1).max(64).regex(IDENTIFIER_PATTERN),
    kmsRootDigests: digestArraySchema,
    channelPinDigests: digestArraySchema,
    upstream: upstreamEvidenceSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.tcbStatus !== EXPECTED_TCB_STATUS ||
      value.upstream.tcbStatus !== EXPECTED_TCB_STATUS
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'TCB must be UpToDate' });
    }
    if (value.tcbStatus !== value.upstream.tcbStatus) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'TCB fields must agree' });
    }
    if (!TEE_VARIANTS.includes(value.upstream.teeVariant as (typeof TEE_VARIANTS)[number])) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'TEE variant is unsupported' });
    }
    if (
      !value.upstream.quoteVerified ||
      !value.upstream.eventLogVerified ||
      !value.upstream.osImageHashVerified ||
      !value.upstream.acpiTablesVerified
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'upstream evidence is incomplete' });
    }
  });

// The session and workload keyset identity are optional at the wire schema so legacy native
// verifier frames remain parseable, but the adapter requires them to form the shared digest.
export const dstackNativeVerificationInputSchema = z
  .object({
    quote: z.string().min(1).max(EVIDENCE_MAX_BYTES),
    collateral: z.string().min(1).max(EVIDENCE_MAX_BYTES),
    eventLog: z.string().min(1).max(EVIDENCE_MAX_BYTES),
    vmConfig: z.string().min(1).max(WIRE_MAX_BYTES),
    sessionId: z.string().min(1).max(256).regex(IDENTIFIER_PATTERN).optional(),
    workloadKeysetDigest: digest64Schema.optional(),
    expected: expectedEvidenceSchema,
  })
  .strict();

export interface DstackEvidenceDigestSet {
  quoteDigest: Digest64;
  collateralDigest: Digest64;
  eventLogDigest: Digest64;
  vmConfigDigest: Digest64;
}

export function parseDstackNativeVerificationInput(
  input: unknown,
): DstackNativeVerificationInputV1 {
  const parsed = dstackNativeVerificationInputSchema.safeParse(input);
  if (!parsed.success) throw new Error('dstack_native_input_invalid');
  decodeBase64(parsed.data.quote, 'quote');
  decodeBase64(parsed.data.collateral, 'collateral');
  return parsed.data;
}

export function computeDstackEvidenceDigests(
  input: DstackNativeVerificationInputV1,
): DstackEvidenceDigestSet {
  const parsed = parseDstackNativeVerificationInput(input);
  const quoteBytes = decodeBase64(parsed.quote, 'quote');
  const collateralBytes = decodeBase64(parsed.collateral, 'collateral');
  return {
    quoteDigest: sha256(quoteBytes),
    collateralDigest: sha256(collateralBytes),
    eventLogDigest: sha256(Buffer.from(parsed.eventLog, 'utf8')),
    vmConfigDigest: sha256(Buffer.from(parsed.vmConfig, 'utf8')),
  };
}

const ZERO_DIGEST_64 = '0'.repeat(64) as Digest64;

// One shared native-evidence identity (plan Task 3): the adapter and the native verifier both
// call digestDstackNativeEvidenceV1 over the same component/identity vector, so every consumer
// of the branded result copies one digest value and never reconstructs it. The identity is
// absent when the session or workload keyset is not supplied; the adapter fails closed then.
export function computeDstackNativeEvidenceDigest(
  input: DstackNativeVerificationInputV1,
): Digest64 {
  if (
    typeof input.sessionId !== 'string' ||
    input.sessionId.length === 0 ||
    typeof input.workloadKeysetDigest !== 'string' ||
    input.workloadKeysetDigest.length === 0
  ) {
    return ZERO_DIGEST_64;
  }
  const evidence: DstackNativeEvidenceV1 = {
    sessionId: input.sessionId,
    workloadKeysetDigest: input.workloadKeysetDigest,
    quoteBase64: input.quote,
    collateralBase64: input.collateral,
    eventLog: input.eventLog,
    vmConfig: input.vmConfig,
    rtmr: input.expected.rtmr,
    runtimeIdentityDigest: input.expected.runtimeIdentityDigest,
    workloadArtifactDigest: input.expected.workloadArtifactDigest,
    routeIdentityDigest: input.expected.routeIdentityDigest,
    tcbStatus: input.expected.tcbStatus,
    kmsRootDigests: [...input.expected.kmsRootDigests],
    channelPinDigests: [...input.expected.channelPinDigests],
    upstream: input.expected.upstream,
  };
  return digestDstackNativeEvidenceV1(evidence).nativeEvidenceDigest as Digest64;
}

export class DstackEvidenceAdapter implements DstackNativeVerifierPort {
  public constructor(private readonly nativeVerifier: DstackNativeVerifierPort) {}

  public async verify(
    input: DstackNativeVerificationInputV1,
  ): Promise<DstackNativeVerificationResultV1> {
    let expected: DstackEvidenceDigestSet;
    let parsed: DstackNativeVerificationInputV1;
    try {
      parsed = parseDstackNativeVerificationInput(input);
      expected = computeDstackEvidenceDigests(parsed);
    } catch {
      return unavailableResult();
    }
    if (
      typeof parsed.sessionId !== 'string' ||
      parsed.sessionId.length === 0 ||
      typeof parsed.workloadKeysetDigest !== 'string' ||
      parsed.workloadKeysetDigest.length === 0
    ) {
      return identityMissingResult();
    }
    const nativeEvidenceDigest = computeDstackNativeEvidenceDigest(parsed);

    let result: DstackNativeVerificationResultV1;
    try {
      result = await this.nativeVerifier.verify(parsed);
    } catch {
      return unavailableResult();
    }
    if (result.failureCode === 'dstack_unavailable') return result;
    if (
      !matchesExpectedResult(result, expected, parsed.expected) ||
      result.nativeEvidenceDigest !== nativeEvidenceDigest
    ) {
      return {
        ...result,
        verdict: 'rejected',
        failureCode: 'native_evidence_failed',
      };
    }
    return result;
  }
}

export function identityMissingResult(): DstackNativeVerificationResultV1 {
  return {
    ...unavailableResult(),
    failureCode: 'native_evidence_failed',
  };
}

export function unavailableResult(): DstackNativeVerificationResultV1 {
  return {
    verdict: 'rejected',
    quoteDigest: zeroDigest(),
    collateralDigest: zeroDigest(),
    eventLogDigest: zeroDigest(),
    vmConfigDigest: zeroDigest(),
    nativeEvidenceDigest: ZERO_DIGEST_64,
    rtmr: '0'.repeat(96),
    runtimeIdentityDigest: zeroDigest(),
    workloadArtifactDigest: zeroDigest(),
    routeIdentityDigest: zeroDigest(),
    tcbStatus: 'unavailable',
    kmsRootDigests: [],
    channelPinDigests: [],
    upstream: {
      quoteVerified: false,
      eventLogVerified: false,
      osImageHashVerified: false,
      acpiTablesVerified: false,
      teeVariant: 'unavailable',
      reportData: '0'.repeat(128),
      tcbStatus: 'unavailable',
      advisoryIds: [],
      appInfo: {
        appIdDigest: zeroDigest(),
        composeHashDigest: zeroDigest(),
        instanceIdDigest: zeroDigest(),
        deviceIdDigest: zeroDigest(),
        mrSystemDigest: zeroDigest(),
        mrAggregatedDigest: zeroDigest(),
        osImageHashDigest: zeroDigest(),
        keyProviderInfoDigest: zeroDigest(),
      },
    },
    failureCode: 'dstack_unavailable',
  };
}

function matchesExpectedResult(
  result: DstackNativeVerificationResultV1,
  expected: DstackEvidenceDigestSet,
  expectedEvidence: DstackNativeExpectedEvidenceV1,
): boolean {
  return (
    result.verdict === 'accepted' &&
    result.failureCode === 'none' &&
    result.quoteDigest === expected.quoteDigest &&
    result.collateralDigest === expected.collateralDigest &&
    result.eventLogDigest === expected.eventLogDigest &&
    result.vmConfigDigest === expected.vmConfigDigest &&
    matchesExpectedEvidence(result, expectedEvidence)
  );
}

function matchesExpectedEvidence(
  result: DstackNativeVerificationResultV1,
  expected: DstackNativeExpectedEvidenceV1,
): boolean {
  return (
    result.rtmr === expected.rtmr &&
    result.runtimeIdentityDigest === expected.runtimeIdentityDigest &&
    result.workloadArtifactDigest === expected.workloadArtifactDigest &&
    result.routeIdentityDigest === expected.routeIdentityDigest &&
    result.tcbStatus === expected.tcbStatus &&
    arraysEqual(result.kmsRootDigests, expected.kmsRootDigests) &&
    arraysEqual(result.channelPinDigests, expected.channelPinDigests) &&
    result.upstream.quoteVerified === expected.upstream.quoteVerified &&
    result.upstream.eventLogVerified === expected.upstream.eventLogVerified &&
    result.upstream.osImageHashVerified === expected.upstream.osImageHashVerified &&
    result.upstream.acpiTablesVerified === expected.upstream.acpiTablesVerified &&
    result.upstream.teeVariant === expected.upstream.teeVariant &&
    result.upstream.reportData === expected.upstream.reportData &&
    result.upstream.tcbStatus === expected.upstream.tcbStatus &&
    arraysEqual(result.upstream.advisoryIds, expected.upstream.advisoryIds) &&
    result.upstream.appInfo.appIdDigest === expected.upstream.appInfo.appIdDigest &&
    result.upstream.appInfo.composeHashDigest === expected.upstream.appInfo.composeHashDigest &&
    result.upstream.appInfo.instanceIdDigest === expected.upstream.appInfo.instanceIdDigest &&
    result.upstream.appInfo.deviceIdDigest === expected.upstream.appInfo.deviceIdDigest &&
    result.upstream.appInfo.mrSystemDigest === expected.upstream.appInfo.mrSystemDigest &&
    result.upstream.appInfo.mrAggregatedDigest === expected.upstream.appInfo.mrAggregatedDigest &&
    result.upstream.appInfo.osImageHashDigest === expected.upstream.appInfo.osImageHashDigest &&
    result.upstream.appInfo.keyProviderInfoDigest ===
      expected.upstream.appInfo.keyProviderInfoDigest
  );
}

function arraysEqual(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function decodeBase64(value: string, label: string): Buffer {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== value) {
    throw new Error(`dstack_${label}_invalid`);
  }
  return decoded;
}

function zeroDigest(): Digest64 {
  return '0'.repeat(64) as Digest64;
}

function sha256(value: Uint8Array | string): Digest64 {
  return createHash('sha256').update(value).digest('hex') as Digest64;
}
