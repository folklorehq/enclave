import { tenantHaltAckKey, tenantHaltKey, tenantHaltRequestKey } from '@folklore/contracts';
import type { Cache, Logger } from '@folklore/core';
import type { TenantRequestQuiescer } from './TenantRequestQuiescer.js';

const DEFAULT_POLL_INTERVAL_MS = 250;
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
}

/** Acknowledges deletion only after Redis fencing and in-process request drain both complete. */
export class TenantRequestQuiescenceMonitor {
  private stopped = false;

  constructor(private readonly options: TenantRequestQuiescenceMonitorOptions) {}

  async runForever(): Promise<void> {
    while (!this.stopped) {
      await this.reconcile();
      if (this.stopped) return;
      await this.delay(this.options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS);
    }
  }

  stop(): void {
    this.stopped = true;
  }

  async reconcile(): Promise<void> {
    const tenantIds = [...new Set(this.options.tenantIds())];
    await Promise.allSettled(tenantIds.map((tenantId) => this.reconcileTenant(tenantId)));
  }

  private async reconcileTenant(tenantId: string): Promise<void> {
    try {
      const [halted, requestId] = await Promise.all([
        this.options.cache.get<boolean>(tenantHaltKey(tenantId)),
        this.options.cache.get<string>(tenantHaltRequestKey(tenantId)),
      ]);
      if (halted !== true) {
        await this.options.onActivate?.(tenantId);
        this.options.quiescer.activate(tenantId);
        return;
      }
      if (!requestId) return;

      await this.drainAndEvict(tenantId);

      const [stillHalted, currentRequestId] = await Promise.all([
        this.options.cache.get<boolean>(tenantHaltKey(tenantId)),
        this.options.cache.get<string>(tenantHaltRequestKey(tenantId)),
      ]);
      if (stillHalted === true && currentRequestId === requestId) {
        await this.options.cache.set(tenantHaltAckKey(tenantId), requestId);
      }
    } catch (error: unknown) {
      this.options.logger.error('tenant_quiescence_probe_failed', {
        error: error instanceof Error ? error.name : 'unknown',
      });
    }
  }

  // A failed eviction must not wait on the drain it may be holding open, or onFence is never retried.
  private async drainAndEvict(tenantId: string): Promise<void> {
    const requestDrain = this.options.quiescer.fence(tenantId);
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
