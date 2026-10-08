import type {
  DurableGenerationHighWaterCheckpointV1,
  GenerationContextV1,
} from '@folklore/contracts';
import type {
  AciTrustContext,
  InferenceBackend,
  VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';

export interface OfficialAciProductionCompositionPort {
  readonly backend: InferenceBackend;
  readonly activePolicySnapshot: VerifiedActivePolicySnapshotV1;
  readonly trustContext: AciTrustContext;
}

export interface ChainedGenerationHighWaterCheckpointV1 extends DurableGenerationHighWaterCheckpointV1 {
  readonly previousCheckpointDigest: string | null;
}

export interface RecentGenerationHighWaterPort {
  readRecent(
    context: GenerationContextV1,
    count: number,
  ): Promise<readonly ChainedGenerationHighWaterCheckpointV1[]>;
}
