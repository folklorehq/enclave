import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { decode, encode, rfc8949EncodeOptions } from 'cborg';
import {
  generationContextV1Schema,
  highWaterLogEntryV1Schema,
  highWaterLogCheckpointV1Schema,
  type GenerationContextV1,
  type HighWaterCandidateV1,
  type HighWaterLogEntryV1,
} from '@folklore/contracts';

export const GENERATION_HIGH_WATER_SIGNING_DOMAIN = 'folklore.generation-high-water.v1' as const;

export class GenerationHighWaterCanonicalError extends Error {
  readonly code:
    | 'high_water_object_invalid'
    | 'high_water_replay_mismatch'
    | 'high_water_entry_digest_mismatch';

  constructor(
    code:
      | 'high_water_object_invalid'
      | 'high_water_replay_mismatch'
      | 'high_water_entry_digest_mismatch',
  ) {
    super(`generation high-water canonical object is invalid: ${code}`);
    this.name = 'GenerationHighWaterCanonicalError';
    this.code = code;
  }
}

export function encodeGenerationHighWaterLogEntryV1(entry: HighWaterLogEntryV1): Uint8Array {
  return encode(highWaterLogEntryV1Schema.parse(entry), rfc8949EncodeOptions);
}

export function decodeGenerationHighWaterLogEntryV1(bytes: Uint8Array): HighWaterLogEntryV1 {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
    throw new GenerationHighWaterCanonicalError('high_water_object_invalid');
  }
  try {
    const parsed = highWaterLogEntryV1Schema.parse(decode(bytes));
    if (!isDeepStrictEqual(encodeGenerationHighWaterLogEntryV1(parsed), bytes)) {
      throw new GenerationHighWaterCanonicalError('high_water_object_invalid');
    }
    return parsed;
  } catch (error: unknown) {
    if (error instanceof GenerationHighWaterCanonicalError) throw error;
    throw new GenerationHighWaterCanonicalError('high_water_object_invalid');
  }
}

export function decodeGenerationHighWaterCandidateV1(input: {
  readonly context: GenerationContextV1;
  readonly entry: HighWaterLogEntryV1;
  readonly bytes: Uint8Array;
}): HighWaterCandidateV1 {
  const context = generationContextV1Schema.parse(input.context);
  const entry = decodeGenerationHighWaterLogEntryV1(input.bytes);
  if (!isDeepStrictEqual(entry, highWaterLogEntryV1Schema.parse(input.entry))) {
    throw new GenerationHighWaterCanonicalError('high_water_replay_mismatch');
  }
  const entryContext = generationContextV1Schema.parse({
    orgId: entry.checkpoint.orgId,
    deploymentId: entry.checkpoint.deploymentId,
    policyDigest: entry.checkpoint.policyDigest,
    policyGeneration: entry.checkpoint.policyGeneration,
    activationGeneration: entry.checkpoint.activationGeneration,
    configurationGeneration: entry.checkpoint.configurationGeneration,
    keysetEpoch: entry.checkpoint.keysetEpoch,
    keysetDigest: entry.checkpoint.keysetDigest,
    releaseId: entry.checkpoint.releaseId,
    protectedSourceCommit: entry.checkpoint.protectedSourceCommit,
    eifDigest: entry.checkpoint.eifDigest,
    pcr0: entry.checkpoint.pcr0,
    bootRootDigest: entry.checkpoint.bootRootDigest,
  });
  if (!isDeepStrictEqual(entryContext, context)) {
    throw new GenerationHighWaterCanonicalError('high_water_replay_mismatch');
  }
  return { context, entry, bytes: Uint8Array.from(input.bytes) };
}

export function generationHighWaterEntryDigestV1(entry: HighWaterLogEntryV1): string {
  const parsed = highWaterLogEntryV1Schema.parse(entry);
  const { entryDigest: _entryDigest, signature: _signature, ...unsigned } = parsed;
  return createHash('sha256').update(encode(unsigned, rfc8949EncodeOptions)).digest('hex');
}

export function generationHighWaterCheckpointDigestV1(
  checkpoint: HighWaterLogEntryV1['checkpoint'],
): string {
  const parsed = highWaterLogCheckpointV1Schema.parse(checkpoint);
  const { checkpointDigest: _checkpointDigest, ...unsigned } = parsed;
  return createHash('sha256').update(encode(unsigned, rfc8949EncodeOptions)).digest('hex');
}

export function generationHighWaterSignatureInputV1(entry: HighWaterLogEntryV1): Uint8Array {
  const parsed = highWaterLogEntryV1Schema.parse(entry);
  const expectedDigest = generationHighWaterEntryDigestV1(parsed);
  if (expectedDigest !== parsed.entryDigest) {
    throw new GenerationHighWaterCanonicalError('high_water_entry_digest_mismatch');
  }
  return Uint8Array.from(
    Buffer.concat([
      Buffer.from(`${GENERATION_HIGH_WATER_SIGNING_DOMAIN}\0`, 'utf8'),
      Buffer.from(expectedDigest, 'hex'),
    ]),
  );
}

export interface GenerationHighWaterSigningMaterial {
  readonly domain: typeof GENERATION_HIGH_WATER_SIGNING_DOMAIN;
  readonly entryDigest: string;
  readonly canonicalBytes: Uint8Array;
}

export function generationHighWaterSigningMaterial(
  entry: HighWaterLogEntryV1,
  storedBytes: Uint8Array,
): GenerationHighWaterSigningMaterial {
  const parsed = decodeGenerationHighWaterLogEntryV1(storedBytes);
  if (!isDeepStrictEqual(parsed, highWaterLogEntryV1Schema.parse(entry))) {
    throw new GenerationHighWaterCanonicalError('high_water_replay_mismatch');
  }
  const entryDigest = generationHighWaterEntryDigestV1(parsed);
  if (entryDigest !== parsed.entryDigest) {
    throw new GenerationHighWaterCanonicalError('high_water_entry_digest_mismatch');
  }
  return {
    domain: GENERATION_HIGH_WATER_SIGNING_DOMAIN,
    entryDigest,
    canonicalBytes: generationHighWaterSignatureInputV1(parsed),
  };
}
