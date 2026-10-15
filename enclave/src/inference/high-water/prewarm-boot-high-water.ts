import {
  toDurableGenerationHighWaterTransportContext,
  type DurableGenerationHighWaterTransportContextV1,
  type GenerationContextV1,
} from '@folklore/contracts';
import type { Logger } from '@folklore/core';
import { guardFailureCode } from '../../boot/guard-failure-code.js';

const PREWARM_FAILED_EVENT = 'boot_high_water_prewarm_failed';

export interface HighWaterWarmPort {
  warm(context: DurableGenerationHighWaterTransportContextV1): Promise<void>;
}

/** Starts reading the boot tenant's chain so the first manifest finds it cached; never rejects. */
export async function prewarmBootHighWater(
  transport: HighWaterWarmPort,
  context: GenerationContextV1,
  logger: Pick<Logger, 'warn'>,
): Promise<void> {
  try {
    await transport.warm(toDurableGenerationHighWaterTransportContext(context));
  } catch (error: unknown) {
    logger.warn(PREWARM_FAILED_EVENT, { reason: guardFailureCode(error, PREWARM_FAILED_EVENT) });
  }
}
