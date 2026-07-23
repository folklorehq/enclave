import type { Logger } from '@folklore/core';

export interface DurableAckItem {
  tenantId: string;
  hasUnsavedInserts(): boolean;
  persist(): Promise<void>;
  ack(): Promise<void>;
}

// Persists every touched tenant index before acking that tenant's SQS messages, so a hard crash can
// only redeliver an un-persisted insert (idempotent via the deterministic factId), never drop it
// from the searchable index. Grouping by tenant keeps per-tenant isolation: one tenant's save
// failure leaves only its messages queued and never acks another tenant's on its behalf.
export class DurableAckBatch {
  private readonly items: DurableAckItem[] = [];

  constructor(private readonly logger: Logger) {}

  add(item: DurableAckItem): void {
    this.items.push(item);
  }

  async commit(): Promise<void> {
    for (const group of this.groupByTenant().values()) {
      const [first] = group;
      if (!first) continue;
      try {
        if (first.hasUnsavedInserts()) await first.persist();
      } catch {
        // Content-free (ADL #18): leave this tenant's batch in queue for redelivery.
        this.logger.error('hnsw persist failed — batch left in queue for retry', {
          tenantId: first.tenantId,
        });
        continue;
      }
      for (const item of group) {
        try {
          await item.ack();
        } catch {
          // A failed delete redelivers and reprocesses idempotently — never crash the drain loop.
          this.logger.error('ack failed — message left in queue for retry', {
            tenantId: item.tenantId,
          });
        }
      }
    }
    this.items.length = 0;
  }

  private groupByTenant(): Map<string, DurableAckItem[]> {
    const groups = new Map<string, DurableAckItem[]>();
    for (const item of this.items) {
      const group = groups.get(item.tenantId) ?? [];
      group.push(item);
      groups.set(item.tenantId, group);
    }
    return groups;
  }
}
