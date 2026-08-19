import type { Logger } from '@folklore/core';

export interface DurableAckItem {
  tenantId: string;
  hasUnsavedInserts(): boolean;
  persist(): Promise<void>;
  afterDurablePersistence?(): Promise<void>;
  afterPersist?(): Promise<void>;
  release?(): Promise<void>;
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
      const persistenceItem = group.find((item) => item.hasUnsavedInserts());
      try {
        if (persistenceItem) await persistenceItem.persist();
      } catch {
        await this.releaseGroup(group);
        // Content-free: leave this tenant's batch in queue for redelivery.
        this.logger.error('hnsw persist failed — batch left in queue for retry', {
          tenantId: first.tenantId,
        });
        continue;
      }
      for (const [index, item] of group.entries()) {
        try {
          await item.afterDurablePersistence?.();
          await item.afterPersist?.();
        } catch {
          await this.releaseGroup(group.slice(index));
          this.logger.error('post-persistence hook failed — batch left in queue for retry', {
            tenantId: item.tenantId,
          });
          break;
        }
        try {
          await item.ack();
        } catch {
          await this.releaseGroup(group.slice(index + 1));
          // A failed delete redelivers and reprocesses idempotently — never crash the drain loop.
          this.logger.error('ack failed — message left in queue for retry', {
            tenantId: item.tenantId,
          });
          break;
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

  private async releaseGroup(group: readonly DurableAckItem[]): Promise<void> {
    for (const item of group) await this.releaseItem(item);
  }

  private async releaseItem(item: DurableAckItem): Promise<void> {
    try {
      await item.release?.();
    } catch {
      this.logger.error('replay release failed — message left in queue for retry', {
        tenantId: item.tenantId,
      });
    }
  }
}
