import { contentFreeErrorType, type Logger } from '@folklore/core';

const MINUTE_MS = 60_000;
export const TENANT_RUNNER_REFRESH_MS = 15 * MINUTE_MS;
export const TENANT_RUNNER_RETRY_MS = 2 * MINUTE_MS;
export const TENANT_RUNNER_TICK_MS = 30_000;

type PassResult = 'settled' | 'retry' | 'failed';

export interface PeriodicTenant {
  readonly tenantId: string;
}

export interface TenantRunnerEvents {
  readonly pass: string;
  readonly skipped: string;
  readonly failed: string;
  readonly passFailed: string;
}

export interface TenantPeriodicRunnerDeps<TTenant extends PeriodicTenant, TOutcome extends string> {
  readonly tenants: () => readonly TTenant[];
  readonly beginTenant: (tenantId: string) => Promise<(() => void) | undefined>;
  readonly runTenant: (tenant: TTenant) => Promise<TOutcome>;
  readonly settledOutcomes: ReadonlySet<TOutcome>;
  readonly events: TenantRunnerEvents;
  // Absent: every failed pass retries after the retry interval.
  readonly backoff?: { readonly maxMs: number };
  readonly logger: Logger;
  readonly now?: () => number;
}

/** Runs one job per assigned tenant on a schedule, one tenant at a time. */
export class TenantPeriodicRunner<TTenant extends PeriodicTenant, TOutcome extends string> {
  private readonly nextDue = new Map<string, number>();
  private readonly failedPasses = new Map<string, number>();
  private readonly now: () => number;
  private inFlight: Promise<void> | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private stopped = false;

  constructor(private readonly deps: TenantPeriodicRunnerDeps<TTenant, TOutcome>) {
    this.now = deps.now ?? Date.now;
  }

  runOnce(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    this.inFlight ??= this.pass().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  start(tickMs = TENANT_RUNNER_TICK_MS): void {
    if (this.timer) return;
    this.tick();
    this.timer = setInterval(() => this.tick(), tickMs);
    this.timer.unref();
  }

  // Shutdown closes the runtime database next, so the tenant being written should finish first; the
  // budget keeps a hung write from starving the rest of shutdown, and closing rolls it back.
  async stop(budgetMs?: number): Promise<boolean> {
    this.stopped = true;
    clearInterval(this.timer);
    this.timer = undefined;
    const pass = this.inFlight;
    if (!pass) return true;
    const settled = pass.then(
      () => true,
      () => true,
    );
    return budgetMs === undefined ? settled : this.withinBudget(settled, budgetMs);
  }

  private async withinBudget(settled: Promise<boolean>, budgetMs: number): Promise<boolean> {
    let budget: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<boolean>((resolve) => {
      budget = setTimeout(() => resolve(false), budgetMs);
    });
    try {
      return await Promise.race([settled, expired]);
    } finally {
      clearTimeout(budget);
    }
  }

  private tick(): void {
    this.runOnce().catch((err: unknown) => {
      this.deps.logger.warn(this.deps.events.passFailed, {
        error_type: contentFreeErrorType(err),
      });
    });
  }

  private async pass(): Promise<void> {
    const tenants = [...this.deps.tenants()].sort((a, b) => this.compareTenants(a, b));
    this.forgetRemoved(tenants);
    for (const tenant of tenants) {
      if (this.stopped) return;
      if (this.isDue(tenant.tenantId)) await this.passTenant(tenant);
    }
  }

  private compareTenants(a: TTenant, b: TTenant): number {
    if (a.tenantId === b.tenantId) return 0;
    return a.tenantId < b.tenantId ? -1 : 1;
  }

  private forgetRemoved(tenants: readonly TTenant[]): void {
    const assigned = new Set(tenants.map((tenant) => tenant.tenantId));
    for (const tenantId of this.nextDue.keys()) {
      if (assigned.has(tenantId)) continue;
      this.nextDue.delete(tenantId);
      this.failedPasses.delete(tenantId);
    }
  }

  private isDue(tenantId: string): boolean {
    const due = this.nextDue.get(tenantId);
    return due === undefined || this.now() >= due;
  }

  private async passTenant(tenant: TTenant): Promise<void> {
    const { tenantId } = tenant;
    const { events } = this.deps;
    let outcome: TOutcome;
    try {
      const release = await this.deps.beginTenant(tenantId);
      if (!release) {
        this.schedule(tenantId, 'retry');
        this.deps.logger.info(events.skipped, { orgId: tenantId });
        return;
      }
      try {
        outcome = await this.deps.runTenant(tenant);
      } finally {
        release();
      }
    } catch (err) {
      this.schedule(tenantId, 'failed');
      // The class name only: a message can quote entries from the response.
      this.deps.logger.warn(events.failed, {
        orgId: tenantId,
        error_type: contentFreeErrorType(err),
      });
      return;
    }
    this.schedule(tenantId, this.deps.settledOutcomes.has(outcome) ? 'settled' : 'retry');
    this.deps.logger.info(events.pass, { orgId: tenantId, outcome });
  }

  private schedule(tenantId: string, result: PassResult): void {
    this.nextDue.set(tenantId, this.now() + this.delayAfter(tenantId, result));
  }

  // Only a thrown pass advances the exponential counter: a skip or an unsettled outcome is not a fault.
  private delayAfter(tenantId: string, result: PassResult): number {
    if (result === 'settled') {
      this.failedPasses.delete(tenantId);
      return TENANT_RUNNER_REFRESH_MS;
    }
    if (result === 'retry') return TENANT_RUNNER_RETRY_MS;
    const passes = (this.failedPasses.get(tenantId) ?? 0) + 1;
    this.failedPasses.set(tenantId, passes);
    const { backoff } = this.deps;
    if (!backoff) return TENANT_RUNNER_RETRY_MS;
    return Math.min(TENANT_RUNNER_RETRY_MS * 2 ** (passes - 1), backoff.maxMs);
  }
}
