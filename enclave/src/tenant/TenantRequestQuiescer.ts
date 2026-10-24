export type TenantRequestRelease = () => void;
// A tenant stays fenced, or its queue work evicted, until every holder that closed it releases it.
export type TenantQuiescenceHolder = 'assignment' | 'halt';

// Calls that name no holder are the assignment applier's; every other caller names its own.
const ASSIGNMENT_FENCE_HOLDER: TenantQuiescenceHolder = 'assignment';

interface TenantRequestState {
  active: number;
  fenced: boolean;
  holders: Set<TenantQuiescenceHolder>;
  workHolders: Set<TenantQuiescenceHolder>;
  fenceEpoch: number;
  idleWaiters: Set<() => void>;
}

/** Fences new tenant requests, waits for admitted requests, and holds queue-work eviction, per holder. */
export class TenantRequestQuiescer {
  private readonly states = new Map<string, TenantRequestState>();
  private nextFenceEpoch = 0;

  begin(tenantId: string): TenantRequestRelease | undefined {
    const state = this.stateFor(tenantId);
    if (state.fenced) return undefined;
    state.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      state.active -= 1;
      if (state.active === 0) this.resolveIdle(state);
    };
  }

  async fence(
    tenantId: string,
    holder: TenantQuiescenceHolder = ASSIGNMENT_FENCE_HOLDER,
  ): Promise<void> {
    const state = this.stateFor(tenantId);
    if (!state.fenced) state.fenceEpoch = ++this.nextFenceEpoch;
    state.holders.add(holder);
    state.fenced = true;
    if (state.active === 0) return;
    await new Promise<void>((resolve) => state.idleWaiters.add(resolve));
  }

  // A new epoch per unfenced-to-fenced transition, so markers from an earlier fence never match.
  currentFenceEpoch(tenantId: string): number | undefined {
    const state = this.states.get(tenantId);
    return state?.fenced ? state.fenceEpoch : undefined;
  }

  activate(tenantId: string, holder: TenantQuiescenceHolder = ASSIGNMENT_FENCE_HOLDER): void {
    const state = this.states.get(tenantId);
    if (!state) return;
    state.holders.delete(holder);
    state.fenced = state.holders.size > 0;
  }

  // Queue-work eviction is held separately because it starts before the request fence is raised.
  holdWork(tenantId: string, holder: TenantQuiescenceHolder = ASSIGNMENT_FENCE_HOLDER): void {
    this.stateFor(tenantId).workHolders.add(holder);
  }

  releaseWork(tenantId: string, holder: TenantQuiescenceHolder = ASSIGNMENT_FENCE_HOLDER): void {
    this.states.get(tenantId)?.workHolders.delete(holder);
  }

  isWorkHeldOnlyBy(tenantId: string, holder: TenantQuiescenceHolder): boolean {
    const holders = this.states.get(tenantId)?.workHolders;
    return holders?.size === 1 && holders.has(holder);
  }

  isWorkHeldBy(tenantId: string, holder: TenantQuiescenceHolder): boolean {
    return this.states.get(tenantId)?.workHolders.has(holder) === true;
  }

  isFenced(tenantId: string): boolean {
    return this.states.get(tenantId)?.fenced === true;
  }

  private stateFor(tenantId: string): TenantRequestState {
    let state = this.states.get(tenantId);
    if (!state) {
      state = {
        active: 0,
        fenced: false,
        holders: new Set(),
        workHolders: new Set(),
        fenceEpoch: 0,
        idleWaiters: new Set(),
      };
      this.states.set(tenantId, state);
    }
    return state;
  }

  private resolveIdle(state: TenantRequestState): void {
    for (const resolve of state.idleWaiters) resolve();
    state.idleWaiters.clear();
  }
}
