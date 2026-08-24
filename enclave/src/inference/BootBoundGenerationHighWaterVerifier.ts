import { createHash, createPublicKey, verify } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type {
  DurableGenerationHighWaterTransportContextV1,
  GenerationHighWaterRuntimeConfigV1,
  HighWaterLogEntryV1,
} from '@folklore/contracts';
import { highWaterLogEntryV1Schema } from '@folklore/contracts';
import { decode, encode, rfc8949EncodeOptions } from 'cborg';
import type { DurableGenerationHighWaterVerifierPort } from './DurableGenerationHighWaterClient.js';

export interface BootBoundGenerationHighWaterVerifierConfig {
  readonly config: GenerationHighWaterRuntimeConfigV1;
}

export class BootBoundGenerationHighWaterVerifier implements DurableGenerationHighWaterVerifierPort {
  readonly purpose = 'generation-high-water' as const;
  private readonly config: GenerationHighWaterRuntimeConfigV1;

  constructor(options: BootBoundGenerationHighWaterVerifierConfig) {
    this.config = options.config;
    const key = createPublicKey({
      key: Buffer.from(this.config.signerPublicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const fingerprint = createHash('sha256')
      .update(key.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    if (fingerprint !== this.config.signerPublicKeyFingerprint) {
      throw new Error('high_water_signer_fingerprint_mismatch');
    }
  }

  async verify(input: {
    purpose: 'generation-high-water';
    context: DurableGenerationHighWaterTransportContextV1;
    entry: HighWaterLogEntryV1;
    bytes: Uint8Array;
  }): Promise<void> {
    if (input.purpose !== this.purpose) throw new Error('high_water_verifier_purpose_invalid');
    if (
      input.entry.signerPurpose !== this.purpose ||
      input.entry.signerKeyId !== this.config.signerKeyId ||
      input.entry.checkpoint.orgId !== input.context.orgId ||
      input.entry.checkpoint.deploymentId !== input.context.deploymentId ||
      input.entry.checkpoint.releaseId !== input.context.releaseId ||
      input.entry.checkpoint.protectedSourceCommit !== input.context.protectedSourceCommit ||
      input.entry.checkpoint.eifDigest !== input.context.eifDigest ||
      input.entry.checkpoint.pcr0 !== input.context.pcr0 ||
      input.entry.checkpoint.bootRootDigest !== input.context.bootRootDigest
    ) {
      throw new Error('high_water_wrong_context');
    }
    const parsed = this.parseCanonicalEntry(input.bytes);
    if (!isDeepStrictEqual(parsed, input.entry)) throw new Error('high_water_replay_mismatch');
    const { entryDigest: _entryDigest, signature: _signature, ...unsigned } = parsed;
    const unsignedBytes = encode(unsigned, rfc8949EncodeOptions);
    const entryDigest = createHash('sha256').update(unsignedBytes).digest('hex');
    if (entryDigest !== parsed.entryDigest) throw new Error('high_water_entry_digest_mismatch');
    const signingBytes = Buffer.concat([
      Buffer.from('folklore.generation-high-water.v1\u0000', 'utf8'),
      Buffer.from(entryDigest, 'hex'),
    ]);
    const key = createPublicKey({
      key: Buffer.from(this.config.signerPublicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
    if (!verify(null, signingBytes, key, Buffer.from(input.entry.signature, 'base64'))) {
      throw new Error('high_water_signature_invalid');
    }
  }

  private parseCanonicalEntry(bytes: Uint8Array): HighWaterLogEntryV1 {
    try {
      const parsed = highWaterLogEntryV1Schema.parse(decode(bytes));
      if (!isDeepStrictEqual(encode(parsed, rfc8949EncodeOptions), bytes)) {
        throw new Error('high_water_noncanonical');
      }
      return parsed;
    } catch (error: unknown) {
      if (error instanceof Error && error.message === 'high_water_noncanonical') throw error;
      throw new Error('high_water_entry_invalid');
    }
  }
}
