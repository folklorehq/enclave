import type { Cache } from '@folklore/core';

/** Redis key the control-plane agent sets/clears to halt this deployment (ADL #13). */
export function haltKey(deploymentId: string): string {
  return `control:halt:${deploymentId}`;
}

/** Cadence at which a halted loop re-reads the flag before touching the queue. */
export const HALT_POLL_INTERVAL_MS = 5_000;

const HALT_READ_MAX_ATTEMPTS = 3;

// Fails toward halted: the flag is read straight from Redis every cycle (never
// cached) and an unreadable flag refuses to process, so a rogue box cannot keep
// decrypting past a halt (ADL #13).
export class HaltGate {
  private readonly key: string;

  constructor(
    private readonly cache: Pick<Cache, 'get'>,
    deploymentId: string,
  ) {
    this.key = haltKey(deploymentId);
  }

  async isHalted(): Promise<boolean> {
    for (let attempt = 1; attempt <= HALT_READ_MAX_ATTEMPTS; attempt += 1) {
      try {
        return Boolean(await this.cache.get(this.key));
      } catch (err) {
        if (attempt === HALT_READ_MAX_ATTEMPTS) {
          console.error('HALT_FLAG_UNREADABLE', { key: this.key, err });
        }
      }
    }
    return true;
  }

  /** Runs `run` only when the flag is clear; returns whether it ran. */
  async guard(run: () => Promise<void>): Promise<boolean> {
    if (await this.isHalted()) return false;
    await run();
    return true;
  }
}
