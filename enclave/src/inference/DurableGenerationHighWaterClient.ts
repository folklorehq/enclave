import { createHash } from 'node:crypto';
import { decode, encode, rfc8949EncodeOptions } from 'cborg';
import {
  DURABLE_GENERATION_HIGH_WATER_CHECKPOINT_V1_SCHEMA,
  digest64Schema,
  durableGenerationHighWaterCheckpointSchema,
  gitCommitSchema,
  highWaterLogEntryV1Schema,
  identifierSchema,
  legacyKeysetHighWater,
  measurement96Schema,
  toDurableGenerationHighWaterTransportContext,
  type DurableGenerationHighWaterCheckpointV1,
  type DurableGenerationHighWaterTransportContextV1,
  type GenerationContextV1,
  type HighWaterLogEntryV1,
} from '@folklore/contracts';
import { ServiceUnavailableError } from '@folklore/errors';
import { isDeepStrictEqual } from 'node:util';

const MAX_HIGH_WATER_CANDIDATE_BYTES = 1_048_576;
const GENERATION_HIGH_WATER_PURPOSE = 'generation-high-water' as const;
const TRANSPORT_CONTEXT_KEYS = [
  'bootRootDigest',
  'deploymentId',
  'eifDigest',
  'orgId',
  'pcr0',
  'protectedSourceCommit',
  'releaseId',
] as const;

export interface HighWaterCandidateV1 {
  context: GenerationContextV1;
  entry: HighWaterLogEntryV1;
  bytes: Uint8Array;
}

export interface DurableGenerationHighWaterEnvelopeV1 {
  entry: HighWaterLogEntryV1;
  bytes: Uint8Array;
}

export interface DurableGenerationHighWaterVerifierPort {
  readonly purpose: typeof GENERATION_HIGH_WATER_PURPOSE;
  verify(input: {
    purpose: typeof GENERATION_HIGH_WATER_PURPOSE;
    context: DurableGenerationHighWaterTransportContextV1;
    entry: HighWaterLogEntryV1;
    bytes: Uint8Array;
  }): Promise<void>;
}

export interface DurableGenerationHighWaterTransport {
  read(
    context: DurableGenerationHighWaterTransportContextV1,
  ): Promise<DurableGenerationHighWaterEnvelopeV1>;
  commit(candidate: {
    context: DurableGenerationHighWaterTransportContextV1;
    entry: HighWaterLogEntryV1;
    bytes: Uint8Array;
  }): Promise<DurableGenerationHighWaterEnvelopeV1>;
}

// The transport verifier (plan Task 2): the request carries only the seven request-bound
// measured-boot identity fields; the signed response carries the complete thirteen-field
// checkpoint. The adapter performs the full-context and durable-floor comparison.
export class DurableGenerationHighWaterClient {
  private readonly transport: DurableGenerationHighWaterTransport;
  private readonly verifier: DurableGenerationHighWaterVerifierPort;

  constructor(
    transport: DurableGenerationHighWaterTransport,
    verifier: DurableGenerationHighWaterVerifierPort,
  ) {
    if (verifier.purpose !== GENERATION_HIGH_WATER_PURPOSE) {
      throw failure('high_water_verifier_purpose_invalid');
    }
    this.transport = transport;
    this.verifier = verifier;
  }

  async read(
    context: DurableGenerationHighWaterTransportContextV1,
  ): Promise<DurableGenerationHighWaterCheckpointV1> {
    const normalizedContext = assertTransportContext(context);
    try {
      const response = await this.transport.read({ ...normalizedContext });
      const envelope = await this.verifyEnvelope(normalizedContext, response, 'response');
      return checkpointFromEntry(envelope.entry);
    } catch (error) {
      if (isHighWaterFailure(error)) throw error;
      throw failure('high_water_response_invalid', error);
    }
  }

  async commit(candidate: HighWaterCandidateV1): Promise<DurableGenerationHighWaterCheckpointV1> {
    const normalizedContext = assertTransportContext(
      toDurableGenerationHighWaterTransportContext(candidate.context),
    );
    if (candidate.bytes.byteLength > MAX_HIGH_WATER_CANDIDATE_BYTES) {
      throw failure('high_water_candidate_too_large');
    }
    const normalizedCandidate = { ...candidate, context: normalizedContext };
    const candidateEnvelope = await this.verifyEnvelope(
      normalizedContext,
      normalizedCandidate,
      'candidate',
    );
    try {
      const response = await this.transport.commit({
        context: normalizedContext,
        entry: candidateEnvelope.entry,
        bytes: Uint8Array.from(candidateEnvelope.bytes),
      });
      const envelope = await this.verifyEnvelope(normalizedContext, response, 'response');
      return checkpointFromEntry(envelope.entry);
    } catch (error) {
      if (isHighWaterFailure(error)) throw error;
      throw failure('high_water_response_invalid', error);
    }
  }

  private async verifyEnvelope(
    context: DurableGenerationHighWaterTransportContextV1,
    input: DurableGenerationHighWaterEnvelopeV1 | HighWaterCandidateV1,
    kind: 'candidate' | 'response',
  ): Promise<DurableGenerationHighWaterEnvelopeV1> {
    const envelope = parseEnvelope(input, kind);
    const entry = parseEntry(envelope.entry, kind);
    const bytes = Uint8Array.from(envelope.bytes);
    assertCanonicalEntryBytes(entry, bytes, kind);
    assertEntryContext(context, entry, kind);
    try {
      await this.verifier.verify({
        purpose: GENERATION_HIGH_WATER_PURPOSE,
        context,
        entry,
        bytes,
      });
    } catch (error) {
      if (isHighWaterFailure(error)) throw error;
      throw failure('high_water_signature_invalid', error);
    }
    return { entry, bytes };
  }
}

// The canonical checkpoint array (digest excluded) in the exact GenerationContextV1 order.
export function durableGenerationHighWaterCheckpointArrayV1(
  checkpoint: Omit<DurableGenerationHighWaterCheckpointV1, 'checkpointDigest'>,
): unknown[] {
  return [
    checkpoint.schema,
    checkpoint.orgId,
    checkpoint.deploymentId,
    checkpoint.policyDigest,
    checkpoint.policyGeneration,
    checkpoint.activationGeneration,
    checkpoint.configurationGeneration,
    checkpoint.keysetEpoch,
    checkpoint.keysetDigest,
    checkpoint.releaseId,
    checkpoint.protectedSourceCommit,
    checkpoint.eifDigest,
    checkpoint.pcr0,
    checkpoint.bootRootDigest,
    checkpoint.predecessorDigest,
    checkpoint.signerKeyId,
    checkpoint.signerPurpose,
  ];
}

export function digestDurableGenerationHighWaterCheckpointV1(
  checkpoint: Omit<DurableGenerationHighWaterCheckpointV1, 'checkpointDigest'>,
): string {
  const domainBytes = Buffer.from(
    `${DURABLE_GENERATION_HIGH_WATER_CHECKPOINT_V1_SCHEMA}\u0000`,
    'utf8',
  );
  const array = durableGenerationHighWaterCheckpointArrayV1(checkpoint);
  const payload = encode(array, rfc8949EncodeOptions);
  return createHash('sha256')
    .update(Buffer.concat([domainBytes, Buffer.from(payload)]))
    .digest('hex');
}

function parseEnvelope(
  input: DurableGenerationHighWaterEnvelopeV1 | HighWaterCandidateV1,
  kind: 'candidate' | 'response',
): DurableGenerationHighWaterEnvelopeV1 {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
    );
  }
  const record = input as unknown as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expectedKeys = kind === 'candidate' ? ['bytes', 'context', 'entry'] : ['bytes', 'entry'];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
    );
  }
  if (!(record['bytes'] instanceof Uint8Array)) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
    );
  }
  return {
    entry: record['entry'] as HighWaterLogEntryV1,
    bytes: record['bytes'],
  };
}

function parseEntry(
  entry: HighWaterLogEntryV1,
  kind: 'candidate' | 'response',
): HighWaterLogEntryV1 {
  try {
    return highWaterLogEntryV1Schema.parse(entry);
  } catch (error) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
      error,
    );
  }
}

function assertCanonicalEntryBytes(
  entry: HighWaterLogEntryV1,
  bytes: Uint8Array,
  kind: 'candidate' | 'response',
): void {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_HIGH_WATER_CANDIDATE_BYTES) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
    );
  }
  let decoded: unknown;
  try {
    decoded = decode(bytes);
  } catch (error) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
      error,
    );
  }
  let parsed: HighWaterLogEntryV1;
  try {
    parsed = highWaterLogEntryV1Schema.parse(decoded);
  } catch (error) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
      error,
    );
  }
  if (
    !isDeepStrictEqual(parsed, entry) ||
    !isDeepStrictEqual(encode(parsed, rfc8949EncodeOptions), bytes)
  ) {
    throw failure(
      kind === 'candidate' ? 'high_water_candidate_invalid' : 'high_water_response_invalid',
    );
  }
  const { entryDigest: _entryDigest, signature: _signature, ...unsigned } = parsed;
  const unsignedBytes = encode(unsigned, rfc8949EncodeOptions);
  if (createHash('sha256').update(unsignedBytes).digest('hex') !== parsed.entryDigest) {
    throw failure('high_water_entry_digest_mismatch');
  }
  const { checkpointDigest: _checkpointDigest, ...unsignedCheckpoint } = parsed.checkpoint;
  if (
    digestDurableGenerationHighWaterCheckpointV1(
      unsignedCheckpoint as Omit<DurableGenerationHighWaterCheckpointV1, 'checkpointDigest'>,
    ) !== parsed.checkpoint.checkpointDigest
  ) {
    throw failure('high_water_checkpoint_digest_mismatch');
  }
}

function assertEntryContext(
  context: DurableGenerationHighWaterTransportContextV1,
  entry: HighWaterLogEntryV1,
  kind: 'candidate' | 'response',
): void {
  const checkpoint = entry.checkpoint;
  if (
    checkpoint.orgId !== context.orgId ||
    checkpoint.deploymentId !== context.deploymentId ||
    checkpoint.releaseId !== context.releaseId ||
    checkpoint.protectedSourceCommit !== context.protectedSourceCommit ||
    checkpoint.eifDigest !== context.eifDigest ||
    checkpoint.pcr0 !== context.pcr0 ||
    checkpoint.bootRootDigest !== context.bootRootDigest ||
    entry.signerPurpose !== GENERATION_HIGH_WATER_PURPOSE ||
    entry.signerKeyId !== checkpoint.signerKeyId ||
    !/^[0-9a-f]{64}$/.test(checkpoint.predecessorDigest ?? '')
  ) {
    throw failure(kind === 'candidate' ? 'high_water_wrong_context' : 'high_water_wrong_context');
  }
}

function assertTransportContext(
  context: DurableGenerationHighWaterTransportContextV1,
): DurableGenerationHighWaterTransportContextV1 {
  if (typeof context !== 'object' || context === null || Array.isArray(context)) {
    throw failure('high_water_wrong_context');
  }
  const keys = Object.keys(context).sort();
  if (
    keys.length !== TRANSPORT_CONTEXT_KEYS.length ||
    keys.some((key, index) => key !== TRANSPORT_CONTEXT_KEYS[index])
  ) {
    throw failure('high_water_wrong_context');
  }
  try {
    return {
      orgId: identifierSchema.parse(context.orgId),
      deploymentId: identifierSchema.parse(context.deploymentId),
      releaseId: identifierSchema.parse(context.releaseId),
      protectedSourceCommit: gitCommitSchema.parse(context.protectedSourceCommit),
      eifDigest: digest64Schema.parse(context.eifDigest),
      pcr0: measurement96Schema.parse(context.pcr0),
      bootRootDigest: digest64Schema.parse(context.bootRootDigest),
    };
  } catch (error) {
    throw failure('high_water_wrong_context', error);
  }
}

function checkpointFromEntry(entry: HighWaterLogEntryV1): DurableGenerationHighWaterCheckpointV1 {
  const checkpoint = entry.checkpoint;
  if (!/^[0-9a-f]{64}$/.test(checkpoint.predecessorDigest ?? '')) {
    throw failure('high_water_missing_predecessor');
  }
  return durableGenerationHighWaterCheckpointSchema.parse({
    checkpointVersion: 1,
    orgId: checkpoint.orgId,
    deploymentId: checkpoint.deploymentId,
    policyDigest: checkpoint.policyDigest,
    policyGeneration: checkpoint.policyGeneration,
    activationGeneration: checkpoint.activationGeneration,
    configurationGeneration: checkpoint.configurationGeneration,
    keysetEpoch: checkpoint.keysetEpoch,
    keysetDigest: checkpoint.keysetDigest,
    ...legacyKeysetHighWater(checkpoint.keysetEpoch, checkpoint.keysetDigest),
    releaseId: checkpoint.releaseId,
    protectedSourceCommit: checkpoint.protectedSourceCommit,
    eifDigest: checkpoint.eifDigest,
    pcr0: checkpoint.pcr0,
    bootRootDigest: checkpoint.bootRootDigest,
    schema: DURABLE_GENERATION_HIGH_WATER_CHECKPOINT_V1_SCHEMA,
    predecessorDigest: checkpoint.predecessorDigest ?? '',
    previousCheckpointDigest: checkpoint.previousCheckpointDigest,
    checkpointDigest: checkpoint.checkpointDigest,
    signerKeyId: checkpoint.signerKeyId,
    signerPurpose: 'generation-high-water',
    issuedAt: checkpoint.issuedAtTrustedMs,
    signature: entry.signature,
  });
}

function isHighWaterFailure(error: unknown): error is ServiceUnavailableError {
  return error instanceof ServiceUnavailableError && error.code.startsWith('high_water_');
}

function failure(code: string, cause?: unknown): ServiceUnavailableError {
  return new ServiceUnavailableError(code, code, { cause, component: 'generation_high_water' });
}
