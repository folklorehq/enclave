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

// Each consecutive refusal doubles the wait, so a deterministic refusal re-verifies rarely, never hot.
export const POLICY_WITHHOLD_BASE_MS = 30_000;
export const POLICY_WITHHOLD_MAX_MS = 15 * 60 * 1000;

interface Withhold {
  readonly snapshot: TenantPolicySnapshotLike;
  readonly refusals: number;
  readonly retryAt: number;
  readonly confirmedAt?: number;
}

export class TenantPolicySnapshotRegistry<
  TSnapshot extends TenantPolicySnapshotLike = TenantPolicySnapshotLike,
  TContext = unknown,
> {
  private readonly withheld = new Map<string, Withhold>();
  private readonly epochs = new Map<string, number>();

  constructor(
    private readonly generationRegistry: TenantGenerationRegistry<TContext, TSnapshot>,
    private readonly now: () => number = () => performance.now(),
  ) {
    generationRegistry.onReplaced(() => this.dropLapsedWithholds());
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
    const installed = this.generationRegistry.get(tenantId)?.snapshot;
    const withhold = this.withheld.get(tenantId);
    if (withhold && withhold.snapshot === installed && this.now() < withhold.retryAt) {
      return undefined;
    }
    return installed;
  }

  refusalEpoch(tenantId: string): number {
    return this.epochs.get(tenantId) ?? 0;
  }

  // Withholds only the snapshot a refusal was raised on; installing any other snapshot lifts it.
  evict(tenantId: string, snapshot: TenantPolicySnapshotLike): boolean {
    if (this.generationRegistry.get(tenantId)?.snapshot !== snapshot) return false;
    this.epochs.set(tenantId, this.refusalEpoch(tenantId) + 1);
    const prior = this.withheld.get(tenantId);
    const now = this.now();
    // Only a failed re-verification escalates; calls in flight when it was raised add nothing.
    if (prior?.snapshot === snapshot && prior.confirmedAt === undefined && now < prior.retryAt) {
      return true;
    }
    const refusals = this.refusalsAfter(prior, snapshot, now) + 1;
    this.withheld.set(tenantId, { snapshot, refusals, retryAt: now + this.backoffMs(refusals) });
    return true;
  }

  // A refusal raised after the epoch was read voids it, so a stale pass cannot lift the newer one.
  confirm(tenantId: string, snapshot: TenantPolicySnapshotLike, epoch: number): void {
    const withhold = this.withheld.get(tenantId);
    if (
      withhold?.snapshot !== snapshot ||
      withhold.confirmedAt !== undefined ||
      this.refusalEpoch(tenantId) !== epoch
    ) {
      return;
    }
    this.withheld.set(tenantId, {
      ...withhold,
      retryAt: Number.NEGATIVE_INFINITY,
      confirmedAt: this.now(),
    });
  }

  // A refusal soon after a pass continues the streak; one after a sustained healthy spell starts over.
  private refusalsAfter(
    prior: Withhold | undefined,
    snapshot: TenantPolicySnapshotLike,
    now: number,
  ): number {
    if (prior?.snapshot !== snapshot) return 0;
    const healthyFor = prior.confirmedAt === undefined ? 0 : now - prior.confirmedAt;
    return healthyFor > POLICY_WITHHOLD_MAX_MS ? 0 : prior.refusals;
  }

  private backoffMs(refusals: number): number {
    const exponent = Math.min(refusals - 1, 30);
    return Math.min(POLICY_WITHHOLD_BASE_MS * 2 ** exponent, POLICY_WITHHOLD_MAX_MS);
  }

  // A removed or re-installed tenant's withhold no longer names an installed snapshot.
  private dropLapsedWithholds(): void {
    for (const [tenantId, withhold] of this.withheld) {
      if (this.generationRegistry.get(tenantId)?.snapshot !== withhold.snapshot) {
        this.withheld.delete(tenantId);
      }
    }
  }
}

function freezeValue<T>(value: T): T {
  if (typeof value === 'object' && value !== null) Object.freeze(value);
  return value;
}
