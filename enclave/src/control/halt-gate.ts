import type { Cache } from '@folklore/core';

/** Redis key the operator break-glass halt command sets/clears (ADL #13). */
export function haltKey(deploymentId: string): string {
  return `control:halt:${deploymentId}`;
}

/** Redis key the billing/commercial enforcement sets/clears — separate owner from the break-glass halt. */
export function licenseHaltKey(deploymentId: string): string {
  return `control:license-halt:${deploymentId}`;
}

/** Cadence at which a halted loop re-reads the flag before touching the queue. */
export const HALT_POLL_INTERVAL_MS = 5_000;

const HALT_READ_MAX_ATTEMPTS = 3;

// Fails toward halted: both flags are read straight from Redis every cycle (never
// cached) and an unreadable flag refuses to process, so a rogue box cannot keep
// decrypting past a halt (ADL #13). Halted when EITHER the operator or the billing
// flag is set.
export class HaltGate {
  private readonly keys: readonly string[];

  constructor(
    private readonly cache: Pick<Cache, 'get'>,
    deploymentId: string,
  ) {
    this.keys = [haltKey(deploymentId), licenseHaltKey(deploymentId)];
  }

  async isHalted(): Promise<boolean> {
    for (let attempt = 1; attempt <= HALT_READ_MAX_ATTEMPTS; attempt += 1) {
      try {
        const flags = await Promise.all(this.keys.map((key) => this.cache.get(key)));
        return flags.some(Boolean);
      } catch (err) {
        if (attempt === HALT_READ_MAX_ATTEMPTS) {
          console.error('HALT_FLAG_UNREADABLE', { keys: this.keys, err });
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
