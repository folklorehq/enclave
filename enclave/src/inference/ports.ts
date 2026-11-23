import type {
  DurableGenerationHighWaterCheckpointV1,
  GenerationContextV1,
} from '@folklore/contracts';

export interface ChainedGenerationHighWaterCheckpointV1 extends DurableGenerationHighWaterCheckpointV1 {
  readonly previousCheckpointDigest: string | null;
}

export interface RecentGenerationHighWaterPort {
  readRecent(
    context: GenerationContextV1,
    count: number,
  ): Promise<readonly ChainedGenerationHighWaterCheckpointV1[]>;
}
