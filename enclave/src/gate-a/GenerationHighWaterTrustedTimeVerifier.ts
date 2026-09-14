import {
  generationHighWaterTrustedTimeRecordV1Schema,
  type GenerationHighWaterTrustedTimeRecordV1,
} from '@folklore/contracts';

import { TRUSTED_TIME_AUTHORITY } from './GenerationHighWaterTrustedTimeRecordProducer.js';

// Enclave-side generation high-water trusted-time verifier. Verifies the
// enclave-produced record: authority, finalized manifest digest binding, exact subject digest,
// boot/checkpoint context, and signature. Rejects rollback and replay against the monotonic floor
// and never treats host wall clocks as freshness authority.

export type GenerationHighWaterTrustedTimeFailureCode =
  | 'authority_invalid'
  | 'manifest_digest_mismatch'
  | 'subject_digest_mismatch'
  | 'boot_context_mismatch'
  | 'checkpoint_missing'
  | 'signature_invalid'
  | 'replay_rejected';

export interface GenerationHighWaterTrustedTimeVerifierInput {
  readonly record: GenerationHighWaterTrustedTimeRecordV1;
  readonly expectedManifestDigest: string;
  readonly expectedSubjectDigest: string;
  readonly expectedBootContextDigest: string;
  readonly replayFloor?: ReadonlySet<string>;
  readonly verifySignature?: (subjectDigest: string, signature: string) => boolean;
}

export interface GenerationHighWaterTrustedTimeVerifierPort {
  verify(input: GenerationHighWaterTrustedTimeVerifierInput): string | undefined;
}

export class GenerationHighWaterTrustedTimeVerifier implements GenerationHighWaterTrustedTimeVerifierPort {
  verify(input: GenerationHighWaterTrustedTimeVerifierInput): string | undefined {
    const parsed = generationHighWaterTrustedTimeRecordV1Schema.safeParse(input.record);
    if (!parsed.success) return 'authority_invalid';
    const record = parsed.data;
    if (record.authority !== TRUSTED_TIME_AUTHORITY) return 'authority_invalid';
    if (record.sourceLineageBinding.manifestDigest !== input.expectedManifestDigest) {
      return 'manifest_digest_mismatch';
    }
    if (record.subjectDigest !== input.expectedSubjectDigest) return 'subject_digest_mismatch';
    if (record.bootContextDigest !== input.expectedBootContextDigest) {
      return 'boot_context_mismatch';
    }
    if (record.checkpointDigest.length !== 64) return 'checkpoint_missing';
    if (input.replayFloor !== undefined && input.replayFloor.has(record.checkpointDigest)) {
      return 'replay_rejected';
    }
    if (input.verifySignature !== undefined) {
      const valid = input.verifySignature(record.signedSubjectDigest, record.signature);
      if (!valid) return 'signature_invalid';
    }
    return undefined;
  }
}
