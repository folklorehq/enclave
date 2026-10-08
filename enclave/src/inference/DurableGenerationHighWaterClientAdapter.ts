import {
  toDurableGenerationHighWaterTransportContext,
  type DurableGenerationHighWaterCheckpointV1,
  type GenerationContextV1,
} from '@folklore/contracts';
import { assertDurableCheckpointAgainstContext } from '@folklore/inference';
import type { DurableGenerationHighWaterClientPort } from '@folklore/inference';
import { DurableGenerationHighWaterClient } from './DurableGenerationHighWaterClient.js';
import type {
  ChainedGenerationHighWaterCheckpointV1,
  RecentGenerationHighWaterPort,
} from './ports.js';

// The only mapping from a complete GenerationContextV1 to the seven request-bound transport
// fields. It projects via the canonical transport projection, calls the transport
// verifier, then performs an exact full-context comparison against the returned signed
// checkpoint before returning it. Missing configurationGeneration, pcr0, bootRootDigest,
// keysetEpoch, keysetDigest, predecessor, org, deployment, or any digest/generation mismatch
// rejects here.
export class DurableGenerationHighWaterClientAdapter
  implements DurableGenerationHighWaterClientPort, RecentGenerationHighWaterPort
{
  constructor(private readonly client: DurableGenerationHighWaterClient) {}

  async read(context: GenerationContextV1): Promise<DurableGenerationHighWaterCheckpointV1> {
    const transportContext = toDurableGenerationHighWaterTransportContext(context);
    const checkpoint = await this.client.read(transportContext);
    assertDurableCheckpointAgainstContext(checkpoint, context);
    this.assertPredecessor(checkpoint);
    return checkpoint;
  }

  // No floor comparison: the caller decides how an installed snapshot relates to these entries.
  async readRecent(
    context: GenerationContextV1,
    count: number,
  ): Promise<readonly ChainedGenerationHighWaterCheckpointV1[]> {
    const checkpoints = await this.client.readRecent(
      toDurableGenerationHighWaterTransportContext(context),
      count,
    );
    for (const checkpoint of checkpoints) this.assertPredecessor(checkpoint);
    return checkpoints;
  }

  private assertPredecessor(checkpoint: DurableGenerationHighWaterCheckpointV1): void {
    if (!/^[0-9a-f]{64}$/.test(checkpoint.predecessorDigest)) {
      throw new Error('high_water_missing_predecessor');
    }
  }
}
