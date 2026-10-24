export const SAVE_COST_STEP_MS = 2_000;
export const MAX_BATCH_FACTOR = 4;
export const SWEEP_COALESCE_BUDGET_MS = 30_000;
export const MIN_EXTEND_HEADROOM_BYTES = 1024 ** 3;
export const MIN_EXTEND_HEAP_HEADROOM_BYTES = 512 * 1024 ** 2;

export interface ExtendHeadroom {
  memAvailableBytes: number;
  liveHeapBytes: number;
  heapLimitBytes: number;
}

export interface SaveCostBatchingOptions {
  clock?: () => number;
  // Past the base target a sweep extends only while this holds.
  canExtend?: () => boolean;
}

// A save rewrites the whole index, so a tenant whose last save was slow takes more messages per sweep and pays for fewer saves.
export class SaveCostBatching {
  private readonly lastSaveMs = new Map<string, number>();
  private readonly clock: () => number;
  private readonly canExtend: () => boolean;

  constructor(
    private readonly baseTarget: number,
    options: SaveCostBatchingOptions = {},
  ) {
    this.clock = options.clock ?? (() => performance.now());
    this.canExtend = options.canExtend ?? (() => true);
  }

  now(): number {
    return this.clock();
  }

  recordSave(tenantId: string, durationMs: number): void {
    this.lastSaveMs.set(tenantId, durationMs);
  }

  forget(tenantId: string): void {
    this.lastSaveMs.delete(tenantId);
  }

  target(tenantId: string): number {
    const steps = Math.floor((this.lastSaveMs.get(tenantId) ?? 0) / SAVE_COST_STEP_MS);
    return this.baseTarget * Math.min(MAX_BATCH_FACTOR, 1 + steps);
  }

  // The budget is the whole sweep's, so held messages stay leased by the visibility heartbeat for a bounded time.
  shouldReceiveMore(tenantId: string, received: number, sweepStartedAt: number): boolean {
    if (received < this.baseTarget) return true;
    if (received >= this.target(tenantId)) return false;
    if (this.clock() - sweepStartedAt >= SWEEP_COALESCE_BUDGET_MS) return false;
    return this.canExtend();
  }
}
