import { tenantHaltAckKey, tenantHaltKey, tenantHaltRequestKey } from '@folklore/contracts';
import type { Cache, Logger } from '@folklore/core';
import type { TenantRequestQuiescer } from './TenantRequestQuiescer.js';

const DEFAULT_POLL_INTERVAL_MS = 250;

export interface TenantRequestQuiescenceMonitorOptions {
  cache: Pick<Cache, 'get' | 'set'>;
  quiescer: TenantRequestQuiescer;
  tenantIds: () => readonly string[];
  logger: Logger;
  onFence?: (tenantId: string) => Promise<void>;
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

      const requestDrain = this.options.quiescer.fence(tenantId);
      const subsystemDrain = this.options.onFence?.(tenantId);
      await Promise.all(
        [requestDrain, subsystemDrain].filter(
          (result): result is Promise<void> => result !== undefined,
        ),
      );

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

  private async delay(milliseconds: number): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
  }
}
