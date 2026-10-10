import { contentFreeErrorType, type Logger } from '@folklore/core';
import type { EntitlementSyncOutcome } from '@folklore/wiki';

const MINUTE_MS = 60_000;
const REFRESH_MS = 15 * MINUTE_MS;
const RETRY_MS = 2 * MINUTE_MS;
const TICK_MS = 30_000;
const SETTLED_OUTCOMES: ReadonlySet<TenantProjectionOutcome> = new Set([
  'applied',
  'skipped_stale',
]);

export interface ProjectionTenant {
  readonly tenantId: string;
  readonly tenantDeploymentId: string;
}

export type TenantProjectionOutcome = EntitlementSyncOutcome | 'database_unavailable';

export interface TenantEntitlementProjectionRunnerDeps {
  readonly tenants: () => readonly ProjectionTenant[];
  readonly beginTenant: (tenantId: string) => Promise<(() => void) | undefined>;
  readonly syncTenant: (tenant: ProjectionTenant) => Promise<TenantProjectionOutcome>;
  readonly logger: Logger;
  readonly now?: () => number;
}

/** Keeps each assigned tenant's entitlement projection current, one tenant at a time. */
export class TenantEntitlementProjectionRunner {
  private readonly nextDue = new Map<string, number>();
  private readonly now: () => number;
  private inFlight: Promise<void> | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private stopped = false;

  constructor(private readonly deps: TenantEntitlementProjectionRunnerDeps) {
    this.now = deps.now ?? Date.now;
  }

  runOnce(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    this.inFlight ??= this.pass().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  start(tickMs = TICK_MS): void {
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
      this.deps.logger.warn('entitlement_projection_pass_failed', {
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

  private compareTenants(a: ProjectionTenant, b: ProjectionTenant): number {
    if (a.tenantId === b.tenantId) return 0;
    return a.tenantId < b.tenantId ? -1 : 1;
  }

  private forgetRemoved(tenants: readonly ProjectionTenant[]): void {
    const assigned = new Set(tenants.map((tenant) => tenant.tenantId));
    for (const tenantId of this.nextDue.keys()) {
      if (!assigned.has(tenantId)) this.nextDue.delete(tenantId);
    }
  }

  private isDue(tenantId: string): boolean {
    const due = this.nextDue.get(tenantId);
    return due === undefined || this.now() >= due;
  }

  private async passTenant(tenant: ProjectionTenant): Promise<void> {
    const { tenantId } = tenant;
    let outcome: TenantProjectionOutcome;
    try {
      const release = await this.deps.beginTenant(tenantId);
      if (!release) {
        this.nextDue.set(tenantId, this.now() + RETRY_MS);
        this.deps.logger.info('entitlement_projection_tenant_skipped', { orgId: tenantId });
        return;
      }
      try {
        outcome = await this.deps.syncTenant(tenant);
      } finally {
        release();
      }
    } catch (err) {
      this.nextDue.set(tenantId, this.now() + RETRY_MS);
      // The class name only: a message can quote roster entries from the response.
      this.deps.logger.warn('entitlement_projection_tenant_failed', {
        orgId: tenantId,
        error_type: contentFreeErrorType(err),
      });
      return;
    }
    const interval = SETTLED_OUTCOMES.has(outcome) ? REFRESH_MS : RETRY_MS;
    this.nextDue.set(tenantId, this.now() + interval);
    this.deps.logger.info('entitlement_projection_tenant_pass', { orgId: tenantId, outcome });
  }
}
