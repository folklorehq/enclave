import { spawn } from 'node:child_process';
import { digest64Schema, type Digest64 } from '@folklore/contracts';
import { z } from 'zod';
import {
  computeDstackEvidenceDigests,
  computeDstackNativeEvidenceDigest,
  parseDstackNativeVerificationInput,
  unavailableResult,
} from './DstackEvidenceAdapter.js';

export const DSTACK_NATIVE_INPUT_MAX_BYTES = 8_388_608;
export const DSTACK_NATIVE_OUTPUT_MAX_BYTES = 65_536;
export const DSTACK_NATIVE_TIMEOUT_MS = 2_000;

const RTMR_PATTERN = /^[0-9a-f]{96}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/+-]*$/;
const ADVISORY_ID_MAX_LENGTH = 128;
const EXPECTED_TCB_STATUS = 'UpToDate';
const TEE_VARIANTS = [
  'dstack-amd-sev-snp',
  'dstack-aws-nitro-tpm',
  'dstack-gcp-tdx',
  'dstack-nitro-enclave',
  'dstack-tdx',
] as const;
const nativeDigestArraySchema = z
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
const advisoryIdsSchema = z
  .array(z.string().min(1).max(ADVISORY_ID_MAX_LENGTH).regex(IDENTIFIER_PATTERN))
  .max(64)
  .superRefine((values, context) => {
    if (values.some((value, index) => value < (values[index - 1] ?? value))) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'advisories must be sorted' });
    }
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'advisories must be unique' });
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
    advisoryIds: advisoryIdsSchema,
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
    kmsRootDigests: nativeDigestArraySchema,
    channelPinDigests: nativeDigestArraySchema,
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
const nativeOutputSchema = z
  .object({
    version: z.literal(1),
    verdict: z.enum(['accepted', 'rejected']),
    quoteDigest: digest64Schema,
    collateralDigest: digest64Schema,
    eventLogDigest: digest64Schema,
    vmConfigDigest: digest64Schema,
    rtmr: z.string().regex(RTMR_PATTERN),
    runtimeIdentityDigest: digest64Schema,
    workloadArtifactDigest: digest64Schema,
    routeIdentityDigest: digest64Schema,
    tcbStatus: z.string().min(1).max(64).regex(IDENTIFIER_PATTERN),
    kmsRootDigests: nativeDigestArraySchema,
    channelPinDigests: nativeDigestArraySchema,
    upstream: upstreamEvidenceSchema,
    failureCode: z.enum(['none', 'native_evidence_failed', 'dstack_unavailable']),
  })
  .strict();

export interface DstackNativeUpstreamAppInfoV1 {
  appIdDigest: Digest64;
  composeHashDigest: Digest64;
  instanceIdDigest: Digest64;
  deviceIdDigest: Digest64;
  mrSystemDigest: Digest64;
  mrAggregatedDigest: Digest64;
  osImageHashDigest: Digest64;
  keyProviderInfoDigest: Digest64;
}

export interface DstackNativeUpstreamEvidenceV1 {
  quoteVerified: boolean;
  eventLogVerified: boolean;
  osImageHashVerified: boolean;
  acpiTablesVerified: boolean;
  teeVariant: string;
  reportData: string;
  tcbStatus: string;
  advisoryIds: readonly string[];
  appInfo: DstackNativeUpstreamAppInfoV1;
}

export interface DstackNativeExpectedEvidenceV1 {
  rtmr: string;
  runtimeIdentityDigest: Digest64;
  workloadArtifactDigest: Digest64;
  routeIdentityDigest: Digest64;
  tcbStatus: string;
  kmsRootDigests: readonly Digest64[];
  channelPinDigests: readonly Digest64[];
  upstream: DstackNativeUpstreamEvidenceV1;
}

export interface DstackNativeVerificationInputV1 {
  quote: string;
  collateral: string;
  eventLog: string;
  vmConfig: string;
  sessionId?: string;
  workloadKeysetDigest?: Digest64;
  expected: DstackNativeExpectedEvidenceV1;
}

export interface DstackNativeVerificationResultV1 {
  verdict: 'accepted' | 'rejected';
  quoteDigest: Digest64;
  runtimeIdentityDigest: Digest64;
  collateralDigest: Digest64;
  eventLogDigest: Digest64;
  vmConfigDigest: Digest64;
  // Always set by the adapter and native verifier at runtime (zero when the session or keyset
  // identity is absent); optional in the type so legacy native fixtures stay compile-compatible.
  nativeEvidenceDigest?: Digest64;
  rtmr: string;
  workloadArtifactDigest: Digest64;
  routeIdentityDigest: Digest64;
  tcbStatus: string;
  kmsRootDigests: readonly Digest64[];
  channelPinDigests: readonly Digest64[];
  upstream: DstackNativeUpstreamEvidenceV1;
  failureCode: 'none' | 'native_evidence_failed' | 'dstack_unavailable';
}

export interface DstackNativeVerifierPort {
  verify(input: DstackNativeVerificationInputV1): Promise<DstackNativeVerificationResultV1>;
}

export interface DstackNativeVerifierOptions {
  executablePath: string;
  args?: readonly string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

type NativeOutput = z.infer<typeof nativeOutputSchema>;

// UNWIRED: production admission remains blocked by the offline-collateral-verification activation gate.
export class DstackNativeVerifier implements DstackNativeVerifierPort {
  readonly #executablePath: string;
  readonly #args: readonly string[];
  readonly #cwd: string | undefined;
  readonly #env: NodeJS.ProcessEnv | undefined;
  readonly #timeoutMs: number;

  public constructor(options: DstackNativeVerifierOptions) {
    if (
      !options ||
      typeof options.executablePath !== 'string' ||
      options.executablePath.length === 0
    ) {
      throw new Error('dstack_executable_invalid');
    }
    const timeoutMs = options.timeoutMs ?? DSTACK_NATIVE_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > DSTACK_NATIVE_TIMEOUT_MS) {
      throw new Error('dstack_timeout_invalid');
    }
    this.#executablePath = options.executablePath;
    this.#args = options.args ?? [];
    this.#cwd = options.cwd;
    this.#env = options.env;
    this.#timeoutMs = timeoutMs;
  }

  public async verify(
    input: DstackNativeVerificationInputV1,
  ): Promise<DstackNativeVerificationResultV1> {
    let parsedInput: DstackNativeVerificationInputV1;
    let expected: ReturnType<typeof computeDstackEvidenceDigests>;
    try {
      parsedInput = parseDstackNativeVerificationInput(input);
      expected = computeDstackEvidenceDigests(parsedInput);
    } catch {
      return unavailableResult();
    }
    if (!expectedEvidenceSchema.safeParse(parsedInput.expected).success) {
      return unavailableResult();
    }

    const inputFrame = encodeFrame(
      JSON.stringify({ version: 1, ...parsedInput }),
      DSTACK_NATIVE_INPUT_MAX_BYTES,
    );
    if (!inputFrame) return unavailableResult();

    const nativeBytes = await this.run(inputFrame);
    if (!nativeBytes) return unavailableResult();

    const native = parseNativeOutput(nativeBytes);
    if (!native) return unavailableResult();
    if (native.failureCode === 'dstack_unavailable') return unavailableResult();
    const nativeEvidenceDigest = computeDstackNativeEvidenceDigest(parsedInput);
    if (!matchesNativeEvidence(native, parsedInput, expected)) {
      return rejectedResult(native, nativeEvidenceDigest);
    }
    return {
      verdict: native.verdict,
      quoteDigest: native.quoteDigest,
      collateralDigest: native.collateralDigest,
      eventLogDigest: native.eventLogDigest,
      vmConfigDigest: native.vmConfigDigest,
      nativeEvidenceDigest,
      rtmr: native.rtmr,
      runtimeIdentityDigest: native.runtimeIdentityDigest,
      workloadArtifactDigest: native.workloadArtifactDigest,
      routeIdentityDigest: native.routeIdentityDigest,
      tcbStatus: native.tcbStatus,
      kmsRootDigests: native.kmsRootDigests,
      channelPinDigests: native.channelPinDigests,
      upstream: native.upstream,
      failureCode: native.failureCode,
    };
  }

  private async run(frame: Buffer): Promise<Buffer | undefined> {
    return new Promise((resolve) => {
      let child;
      try {
        child = spawn(this.#executablePath, [...this.#args], {
          cwd: this.#cwd,
          env: this.#env,
          stdio: ['pipe', 'pipe', 'ignore'],
        });
      } catch {
        resolve(undefined);
        return;
      }

      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      let timedOut = false;
      let oversized = false;
      const timeout = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, this.#timeoutMs);

      const finish = (value: Buffer | undefined): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve(value);
      };

      child.stdout.on('data', (chunk: Buffer) => {
        total += chunk.byteLength;
        if (total > DSTACK_NATIVE_OUTPUT_MAX_BYTES + 4) {
          oversized = true;
          child.kill('SIGKILL');
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      child.once('error', () => finish(undefined));
      child.once('close', (code) => {
        if (timedOut || oversized || code !== 0) {
          finish(undefined);
          return;
        }
        finish(Buffer.concat(chunks, total));
      });
      child.stdin.once('error', () => finish(undefined));
      child.stdin.end(frame);
    });
  }
}

function encodeFrame(payload: string, maximum: number): Buffer | undefined {
  const body = Buffer.from(payload, 'utf8');
  if (body.byteLength === 0 || body.byteLength > maximum) return undefined;
  const frame = Buffer.allocUnsafe(body.byteLength + 4);
  frame.writeUInt32BE(body.byteLength, 0);
  body.copy(frame, 4);
  return frame;
}

function parseNativeOutput(bytes: Buffer): NativeOutput | undefined {
  if (bytes.byteLength < 4) return undefined;
  const declaredLength = bytes.readUInt32BE(0);
  if (declaredLength === 0 || declaredLength > DSTACK_NATIVE_OUTPUT_MAX_BYTES) return undefined;
  if (bytes.byteLength !== declaredLength + 4) return undefined;
  const raw = bytes.subarray(4).toString('utf8');
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (JSON.stringify(decoded) !== raw) return undefined;
  const parsed = nativeOutputSchema.safeParse(decoded);
  return parsed.success ? parsed.data : undefined;
}

function matchesNativeEvidence(
  native: NativeOutput,
  input: DstackNativeVerificationInputV1,
  expected: ReturnType<typeof computeDstackEvidenceDigests>,
): boolean {
  return (
    native.quoteDigest === expected.quoteDigest &&
    native.collateralDigest === expected.collateralDigest &&
    native.eventLogDigest === expected.eventLogDigest &&
    native.vmConfigDigest === expected.vmConfigDigest &&
    native.rtmr === input.expected.rtmr &&
    native.runtimeIdentityDigest === input.expected.runtimeIdentityDigest &&
    native.workloadArtifactDigest === input.expected.workloadArtifactDigest &&
    native.routeIdentityDigest === input.expected.routeIdentityDigest &&
    native.tcbStatus === input.expected.tcbStatus &&
    native.tcbStatus === native.upstream.tcbStatus &&
    arraysEqual(native.kmsRootDigests, input.expected.kmsRootDigests) &&
    arraysEqual(native.channelPinDigests, input.expected.channelPinDigests) &&
    matchesUpstreamEvidence(native.upstream, input.expected.upstream) &&
    ((native.verdict === 'accepted' && native.failureCode === 'none') ||
      (native.verdict === 'rejected' && native.failureCode === 'native_evidence_failed'))
  );
}

function matchesUpstreamEvidence(
  actual: DstackNativeUpstreamEvidenceV1,
  expected: DstackNativeUpstreamEvidenceV1,
): boolean {
  return (
    actual.quoteVerified === expected.quoteVerified &&
    actual.eventLogVerified === expected.eventLogVerified &&
    actual.osImageHashVerified === expected.osImageHashVerified &&
    actual.acpiTablesVerified === expected.acpiTablesVerified &&
    actual.teeVariant === expected.teeVariant &&
    actual.reportData === expected.reportData &&
    actual.tcbStatus === expected.tcbStatus &&
    arraysEqual(actual.advisoryIds, expected.advisoryIds) &&
    actual.appInfo.appIdDigest === expected.appInfo.appIdDigest &&
    actual.appInfo.composeHashDigest === expected.appInfo.composeHashDigest &&
    actual.appInfo.instanceIdDigest === expected.appInfo.instanceIdDigest &&
    actual.appInfo.deviceIdDigest === expected.appInfo.deviceIdDigest &&
    actual.appInfo.mrSystemDigest === expected.appInfo.mrSystemDigest &&
    actual.appInfo.mrAggregatedDigest === expected.appInfo.mrAggregatedDigest &&
    actual.appInfo.osImageHashDigest === expected.appInfo.osImageHashDigest &&
    actual.appInfo.keyProviderInfoDigest === expected.appInfo.keyProviderInfoDigest
  );
}

function arraysEqual(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function rejectedResult(
  native: NativeOutput,
  nativeEvidenceDigest: Digest64,
): DstackNativeVerificationResultV1 {
  return {
    verdict: 'rejected',
    quoteDigest: native.quoteDigest,
    collateralDigest: native.collateralDigest,
    eventLogDigest: native.eventLogDigest,
    vmConfigDigest: native.vmConfigDigest,
    nativeEvidenceDigest,
    rtmr: native.rtmr,
    runtimeIdentityDigest: native.runtimeIdentityDigest,
    workloadArtifactDigest: native.workloadArtifactDigest,
    routeIdentityDigest: native.routeIdentityDigest,
    tcbStatus: native.tcbStatus,
    kmsRootDigests: native.kmsRootDigests,
    channelPinDigests: native.channelPinDigests,
    upstream: native.upstream,
    failureCode: 'native_evidence_failed',
  };
}
