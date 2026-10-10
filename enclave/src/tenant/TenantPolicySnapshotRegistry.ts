import type { TenantGenerationRegistry } from './TenantGenerationRegistry.js';

export interface TenantPolicySnapshotLike {
  readonly tenantId: string;
}

class ReadonlySnapshotMap<TSnapshot extends TenantPolicySnapshotLike> implements ReadonlyMap<
  string,
  TSnapshot
> {
  private readonly map: Map<string, TSnapshot>;

  constructor(entries: Iterable<readonly [string, TSnapshot]>) {
    this.map = new Map(entries);
  }

  get size(): number {
    return this.map.size;
  }

  get(key: string): TSnapshot | undefined {
    return this.map.get(key);
  }

  has(key: string): boolean {
    return this.map.has(key);
  }

  entries(): MapIterator<[string, TSnapshot]> {
    return this.map.entries();
  }

  keys(): MapIterator<string> {
    return this.map.keys();
  }

  values(): MapIterator<TSnapshot> {
    return this.map.values();
  }

  forEach(
    callbackfn: (value: TSnapshot, key: string, map: ReadonlyMap<string, TSnapshot>) => void,
  ): void {
    this.map.forEach((value, key) => callbackfn(value, key, this));
  }

  [Symbol.iterator](): MapIterator<[string, TSnapshot]> {
    return this.entries();
  }
}

export class TenantPolicySnapshotRegistry<
  TSnapshot extends TenantPolicySnapshotLike = TenantPolicySnapshotLike,
  TContext = unknown,
> {
  private readonly evicted = new Map<string, TenantPolicySnapshotLike>();

  constructor(private readonly generationRegistry: TenantGenerationRegistry<TContext, TSnapshot>) {
    generationRegistry.onReplaced(() => this.dropLapsedEvictions());
  }

  stage(snapshots: ReadonlyMap<string, TSnapshot>): ReadonlyMap<string, TSnapshot> {
    const staged: Array<readonly [string, TSnapshot]> = [];
    for (const [tenantId, snapshot] of snapshots) {
      if (snapshot.tenantId !== tenantId) {
        throw new Error('tenant_policy_snapshot_tenant_mismatch');
      }
      staged.push([tenantId, freezeValue(snapshot)]);
    }
    return new ReadonlySnapshotMap(staged);
  }

  get(tenantId: string): TSnapshot | undefined {
    if (this.evicted.has(tenantId)) return undefined;
    return this.generationRegistry.get(tenantId)?.snapshot;
  }

  // Withholds only the snapshot a refusal was raised on; installing any other snapshot lifts it.
  evict(tenantId: string, snapshot: TenantPolicySnapshotLike): void {
    if (this.generationRegistry.get(tenantId)?.snapshot !== snapshot) return;
    this.evicted.set(tenantId, snapshot);
  }

  // A removed or re-installed tenant's eviction no longer names an installed snapshot.
  private dropLapsedEvictions(): void {
    for (const [tenantId, snapshot] of this.evicted) {
      if (this.generationRegistry.get(tenantId)?.snapshot !== snapshot) {
        this.evicted.delete(tenantId);
      }
    }
  }
}

function freezeValue<T>(value: T): T {
  if (typeof value === 'object' && value !== null) Object.freeze(value);
  return value;
}
