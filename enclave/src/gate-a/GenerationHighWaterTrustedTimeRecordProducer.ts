import {
  generationHighWaterTrustedTimeRecordV1Schema,
  type GenerationHighWaterTrustedTimeRecordV1,
  type TrustedTimeBindingV1,
  type TrustedTimeSampleV1,
} from '@folklore/contracts';
import { canonicalJson, sha256Hex } from '@folklore/utils';

// PR6 enclave-side generation high-water trusted-time producer (plan Step 6). The producer is
// wired by the runtime attestation composition to the origin/main TrustedTimeAuthority and the
// enclave evidence key. It samples verified NSM plus CLOCK_MONOTONIC_RAW, binds the
// boot/enclave-checkpoint/sample context and the requested subject digest, and returns only the
// signed record. Host wall clocks, NTP, AWS servedAt, and operator timestamps are never authority.

export const TRUSTED_TIME_AUTHORITY = 'NSM+CLOCK_MONOTONIC_RAW' as const;

export interface GenerationHighWaterTrustedTimeSamplePort {
  sample(binding: TrustedTimeBindingV1): Promise<TrustedTimeSampleV1>;
}

export interface GenerationHighWaterTrustedTimeSignerPort {
  sign(subjectDigest: string): Promise<{ keyId: string; signature: string }>;
}

export interface GenerationHighWaterTrustedTimeRecordProducerOptions {
  readonly binding: TrustedTimeBindingV1;
  readonly sampler: GenerationHighWaterTrustedTimeSamplePort;
  readonly signer: GenerationHighWaterTrustedTimeSignerPort;
}

export interface GenerationHighWaterTrustedTimeProduceInput {
  readonly subjectKind: 'H3-high-water-evidence' | 'H5-live-acceptance';
  readonly subjectDigest: string;
  readonly sourceManifestPath: string;
  readonly sourceManifestDigest: string;
  readonly manifestStage: 'H3-high-water-evidence' | 'H5-live';
  readonly bootContextDigest: string;
}

export class GenerationHighWaterTrustedTimeRecordProducer {
  constructor(private readonly options: GenerationHighWaterTrustedTimeRecordProducerOptions) {}

  async produce(
    input: GenerationHighWaterTrustedTimeProduceInput,
  ): Promise<GenerationHighWaterTrustedTimeRecordV1> {
    const sample = await this.options.sampler.sample(this.options.binding);
    const withoutSignature = {
      schema: 'GenerationHighWaterTrustedTimeRecordV1',
      version: 1,
      subjectKind: input.subjectKind,
      subjectDigest: input.subjectDigest,
      binding: this.options.binding,
      sample,
      sourceLineageBinding: {
        manifestStage: input.manifestStage,
        manifestPath: input.sourceManifestPath,
        manifestDigest: input.sourceManifestDigest,
      },
      bootContextDigest: input.bootContextDigest,
      checkpointDigest: sample.checkpointDigest,
      authority: TRUSTED_TIME_AUTHORITY,
      enclaveEvidenceKeyId: '',
      signedSubjectDigest: '',
      signature: '',
      noCustomerContent: true,
      liveEvidence: null,
    };
    const signedSubjectDigest = sha256Hex(
      canonicalJson({
        schema: withoutSignature.schema,
        version: withoutSignature.version,
        subjectKind: withoutSignature.subjectKind,
        subjectDigest: withoutSignature.subjectDigest,
        binding: withoutSignature.binding,
        sample: withoutSignature.sample,
        sourceLineageBinding: withoutSignature.sourceLineageBinding,
        bootContextDigest: withoutSignature.bootContextDigest,
        checkpointDigest: withoutSignature.checkpointDigest,
        authority: withoutSignature.authority,
      }),
    );
    const signed = await this.options.signer.sign(signedSubjectDigest);
    return generationHighWaterTrustedTimeRecordV1Schema.parse({
      ...withoutSignature,
      enclaveEvidenceKeyId: signed.keyId,
      signedSubjectDigest,
      signature: signed.signature,
    });
  }
}
