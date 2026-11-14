import { ServiceUnavailableError } from '@folklore/errors';

export type TenantRequestRelease = () => void;
// A tenant stays fenced, or its queue work evicted, until every holder that closed it releases it.
export type TenantQuiescenceHolder = 'assignment' | 'halt';

// Calls that name no holder are the assignment applier's; every other caller names its own.
const ASSIGNMENT_FENCE_HOLDER: TenantQuiescenceHolder = 'assignment';
const TENANT_FENCED_CODE = 'tenant_unavailable';

interface TenantRequestState {
  active: number;
  fenced: boolean;
  holders: Set<TenantQuiescenceHolder>;
  workHolders: Set<TenantQuiescenceHolder>;
  fenceEpoch: number;
  fenceAbort: AbortController;
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
    const wasFenced = state.fenced;
    state.holders.add(holder);
    state.fenced = true;
    // The abort fires last, so a synchronous listener already sees the tenant fenced at its new epoch.
    if (!wasFenced) {
      state.fenceEpoch = ++this.nextFenceEpoch;
      state.fenceAbort.abort(new ServiceUnavailableError('tenant fenced', TENANT_FENCED_CODE));
    }
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
    const wasFenced = state.fenced;
    state.holders.delete(holder);
    state.fenced = state.holders.size > 0;
    // Only a real unfence renews it: the halt monitor activates every unhalted tenant on every poll.
    if (wasFenced && !state.fenced) state.fenceAbort = new AbortController();
  }

  // Aborts when the tenant is next fenced, and stays aborted while it is.
  fenceSignal(tenantId: string): AbortSignal {
    return this.stateFor(tenantId).fenceAbort.signal;
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

  isWorkHeld(tenantId: string): boolean {
    return (this.states.get(tenantId)?.workHolders.size ?? 0) > 0;
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
        fenceAbort: new AbortController(),
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
