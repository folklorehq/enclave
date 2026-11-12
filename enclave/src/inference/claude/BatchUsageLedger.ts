import type { InferenceUsageEvent, InferenceUsageSink } from '@folklore/inference';

interface Parked {
  readonly total: InferenceUsageEvent;
  readonly calls: number;
}

const sum = (a: number | undefined, b: number | undefined): number | undefined =>
  a === undefined && b === undefined ? undefined : (a ?? 0) + (b ?? 0);

/** Holds the usage of batches harvested outside the org's own run until that run can report it. */
export class BatchUsageLedger {
  private readonly parked = new Map<string, Map<string, Parked>>();

  constructor(
    private readonly sink: InferenceUsageSink,
    private readonly recordingFor: (orgId: string) => boolean,
  ) {}

  record(orgId: string, event: InferenceUsageEvent): void {
    if (this.recordingFor(orgId)) this.sink(event);
    else this.park(orgId, event);
  }

  /** Call inside that org's run: elsewhere the events stay parked rather than being dropped. */
  flush(orgId: string): void {
    const entries = this.parked.get(orgId);
    if (entries === undefined || !this.recordingFor(orgId)) return;
    this.parked.delete(orgId);
    for (const { total, calls } of entries.values()) {
      this.sink(total);
      for (let extra = 1; extra < calls; extra += 1) this.sink(this.callOnly(total));
    }
  }

  private park(orgId: string, event: InferenceUsageEvent): void {
    const entries = this.parked.get(orgId) ?? new Map<string, Parked>();
    const key = JSON.stringify([event.model, event.operation, event.purpose, event.outcome]);
    const held = entries.get(key);
    entries.set(key, held === undefined ? { total: event, calls: 1 } : this.merged(held, event));
    this.parked.set(orgId, entries);
  }

  private merged(held: Parked, event: InferenceUsageEvent): Parked {
    const { total } = held;
    const cacheReadTokens = sum(total.cacheReadTokens, event.cacheReadTokens);
    const cacheWriteTokens = sum(total.cacheWriteTokens, event.cacheWriteTokens);
    const cacheWrite1hTokens = sum(total.cacheWrite1hTokens, event.cacheWrite1hTokens);
    return {
      calls: held.calls + 1,
      total: {
        ...total,
        promptTokens: total.promptTokens + event.promptTokens,
        completionTokens: total.completionTokens + event.completionTokens,
        ...(cacheReadTokens === undefined ? {} : { cacheReadTokens }),
        ...(cacheWriteTokens === undefined ? {} : { cacheWriteTokens }),
        ...(cacheWrite1hTokens === undefined ? {} : { cacheWrite1hTokens }),
      },
    };
  }

  // Counts a call without adding tokens, so the merged entry still reports every call it stands for.
  private callOnly(total: InferenceUsageEvent): InferenceUsageEvent {
    return {
      ...total,
      promptTokens: 0,
      completionTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      cacheWrite1hTokens: 0,
    };
  }
}
