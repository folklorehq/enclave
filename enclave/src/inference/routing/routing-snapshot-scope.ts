import { AsyncLocalStorage } from 'node:async_hooks';
import type { InferencePurpose, PurposeRoute } from '@folklore/contracts';

export interface RoutingSnapshot {
  readonly orgId: string;
  readonly version: number;
  readonly purposes: Readonly<Record<InferencePurpose, PurposeRoute>>;
}

class RoutingSnapshotStore {
  private readonly storage = new AsyncLocalStorage<RoutingSnapshot>();

  run<T>(snapshot: RoutingSnapshot, fn: () => Promise<T>): Promise<T> {
    return this.storage.run(snapshot, fn);
  }

  current(): RoutingSnapshot | undefined {
    return this.storage.getStore();
  }
}

export const routingSnapshotScope = new RoutingSnapshotStore();
