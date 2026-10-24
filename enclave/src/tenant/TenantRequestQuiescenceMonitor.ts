import { tenantHaltAckKey, tenantHaltKey, tenantHaltRequestKey } from '@folklore/contracts';
import type { Cache, Logger } from '@folklore/core';
import type { TenantQuiescenceHolder, TenantRequestQuiescer } from './TenantRequestQuiescer.js';

const DEFAULT_POLL_INTERVAL_MS = 250;
// Nothing halted means nothing to acknowledge; a halt costs at most this much extra before it is noticed, and request admission checks the flag itself in the meantime.
const DEFAULT_IDLE_POLL_INTERVAL_MS = 1_000;
const HALT_FENCE_HOLDER: TenantQuiescenceHolder = 'halt';
const STILL_DRAINING = Symbol('still_draining');

export interface TenantRequestQuiescenceMonitorOptions {
  cache: Pick<Cache, 'get' | 'set'>;
  quiescer: TenantRequestQuiescer;
  tenantIds: () => readonly string[];
  logger: Logger;
  onFence?: (tenantId: string) => Promise<void>;
  // Runs after admitted requests drain, for state an admitted request could rebuild.
  onDrained?: (tenantId: string) => Promise<void>;
  onActivate?: (tenantId: string) => void | Promise<void>;
  pollIntervalMs?: number;
  idlePollIntervalMs?: number;
}

/** Acknowledges deletion only after Redis fencing and in-process request drain both complete. */
export class TenantRequestQuiescenceMonitor {
  private stopped = false;

  constructor(private readonly options: TenantRequestQuiescenceMonitorOptions) {}

  async runForever(): Promise<void> {
    while (!this.stopped) {
      const engaged = await this.reconcile();
      if (this.stopped) return;
      await this.delay(this.pollIntervalFor(engaged));
    }
  }

  stop(): void {
    this.stopped = true;
  }

  // True while any tenant is halted or still holding what a halt closed, so the caller polls fast only then.
  async reconcile(): Promise<boolean> {
    const tenantIds = [...new Set(this.options.tenantIds())];
    const outcomes = await Promise.allSettled(
      tenantIds.map((tenantId) => this.reconcileTenant(tenantId)),
    );
    return outcomes.some((outcome) => outcome.status === 'fulfilled' && outcome.value);
  }

  private pollIntervalFor(engaged: boolean): number {
    return engaged
      ? (this.options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS)
      : (this.options.idlePollIntervalMs ?? DEFAULT_IDLE_POLL_INTERVAL_MS);
  }

  private async reconcileTenant(tenantId: string): Promise<boolean> {
    try {
      const halted = await this.options.cache.get<boolean>(tenantHaltKey(tenantId));
      if (halted !== true) {
        await this.releaseHalt(tenantId);
        return this.options.quiescer.isWorkHeldBy(tenantId, HALT_FENCE_HOLDER);
      }
      const requestId = await this.options.cache.get<string>(tenantHaltRequestKey(tenantId));
      if (!requestId) return true;

      await this.drainAndEvict(tenantId);

      const [stillHalted, currentRequestId] = await Promise.all([
        this.options.cache.get<boolean>(tenantHaltKey(tenantId)),
        this.options.cache.get<string>(tenantHaltRequestKey(tenantId)),
      ]);
      if (stillHalted === true && currentRequestId === requestId) {
        await this.options.cache.set(tenantHaltAckKey(tenantId), requestId);
      }
      return true;
    } catch (error: unknown) {
      this.options.logger.error('tenant_quiescence_probe_failed', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      return true;
    }
  }

  // The applier fences and evicts too; only what this monitor closed for a halt reopens here.
  private async releaseHalt(tenantId: string): Promise<void> {
    const { quiescer } = this.options;
    quiescer.activate(tenantId, HALT_FENCE_HOLDER);
    if (!quiescer.isWorkHeldOnlyBy(tenantId, HALT_FENCE_HOLDER)) return;
    if (quiescer.currentFenceEpoch(tenantId) !== undefined) return;
    await this.options.onActivate?.(tenantId);
    quiescer.releaseWork(tenantId, HALT_FENCE_HOLDER);
  }

  // A failed eviction must not wait on the drain it may be holding open, or onFence is never retried.
  private async drainAndEvict(tenantId: string): Promise<void> {
    this.options.quiescer.holdWork(tenantId, HALT_FENCE_HOLDER);
    const requestDrain = this.options.quiescer.fence(tenantId, HALT_FENCE_HOLDER);
    requestDrain.catch(() => undefined);
    try {
      await this.options.onFence?.(tenantId);
    } catch (error: unknown) {
      if (await this.hasDrained(requestDrain)) await this.options.onDrained?.(tenantId);
      throw error;
    }
    await requestDrain;
    await this.options.onDrained?.(tenantId);
  }

  // Racing the promise itself against an already-resolved sentinel observes a settled drain deterministically.
  private async hasDrained(requestDrain: Promise<void>): Promise<boolean> {
    try {
      return (
        (await Promise.race([requestDrain, Promise.resolve(STILL_DRAINING)])) !== STILL_DRAINING
      );
    } catch {
      return false;
    }
  }

  private async delay(milliseconds: number): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
  }
}
