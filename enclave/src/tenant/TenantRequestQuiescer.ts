export type TenantRequestRelease = () => void;

interface TenantRequestState {
  active: number;
  fenced: boolean;
  idleWaiters: Set<() => void>;
}

/** Fences new tenant requests and waits for admitted requests before context zeroization. */
export class TenantRequestQuiescer {
  private readonly states = new Map<string, TenantRequestState>();

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

  async fence(tenantId: string): Promise<void> {
    const state = this.stateFor(tenantId);
    state.fenced = true;
    if (state.active === 0) return;
    await new Promise<void>((resolve) => state.idleWaiters.add(resolve));
  }

  activate(tenantId: string): void {
    this.stateFor(tenantId).fenced = false;
  }

  private stateFor(tenantId: string): TenantRequestState {
    let state = this.states.get(tenantId);
    if (!state) {
      state = { active: 0, fenced: false, idleWaiters: new Set() };
      this.states.set(tenantId, state);
    }
    return state;
  }

  private resolveIdle(state: TenantRequestState): void {
    for (const resolve of state.idleWaiters) resolve();
    state.idleWaiters.clear();
  }
}
