import { contentFreeErrorType, type Logger } from '@folklore/core';

const MINUTE_MS = 60_000;
export const TENANT_RUNNER_REFRESH_MS = 15 * MINUTE_MS;
export const TENANT_RUNNER_RETRY_MS = 2 * MINUTE_MS;
export const TENANT_RUNNER_TICK_MS = 30_000;
export const TENANT_RUNNER_EXPEDITE_GAP_MS = MINUTE_MS;
export const TENANT_RUNNER_SIGNAL_TIMEOUT_MS = 5_000;

const NO_SIGNAL: ReadonlyMap<string, string> = new Map();

type PassResult = 'settled' | 'retry' | 'failed';

class SignalTimeoutError extends Error {
  constructor() {
    super('signal read timed out');
    this.name = 'SignalTimeoutError';
  }
}

export interface PeriodicTenant {
  readonly tenantId: string;
}

/** Per-tenant values that, when they change, make the tenant due sooner. */
export interface TenantExpediteSignal {
  read(): Promise<ReadonlyMap<string, string>>;
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
  readonly intervals?: { readonly refreshMs: number; readonly retryMs: number };
  // Only ever brings an assigned tenant's next pass forward, at most once per expedite gap.
  readonly expediteSignal?: TenantExpediteSignal;
  readonly logger: Logger;
  readonly now?: () => number;
}

/** Runs one job per assigned tenant on a schedule, one tenant at a time. */
export class TenantPeriodicRunner<TTenant extends PeriodicTenant, TOutcome extends string> {
  private readonly nextDue = new Map<string, number>();
  private readonly failedPasses = new Map<string, number>();
  private readonly signalAtPassStart = new Map<string, string>();
  private readonly lastExpeditedAt = new Map<string, number>();
  private signalFailing = false;
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
    const signal = await this.readSignal();
    for (const tenant of tenants) {
      if (this.stopped) return;
      const { tenantId } = tenant;
      if (this.isDue(tenantId) || this.isExpedited(tenantId, signal)) {
        await this.passTenant(tenant, signal);
      }
    }
  }

  private async readSignal(): Promise<ReadonlyMap<string, string>> {
    const { expediteSignal, logger } = this.deps;
    if (!expediteSignal) return NO_SIGNAL;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new SignalTimeoutError()), TENANT_RUNNER_SIGNAL_TIMEOUT_MS);
    });
    try {
      const values = await Promise.race([expediteSignal.read(), timedOut]);
      this.signalFailing = false;
      return values;
    } catch (err) {
      if (!this.signalFailing) {
        logger.warn('tenant_runner_signal_unavailable', { error_type: contentFreeErrorType(err) });
      }
      this.signalFailing = true;
      return NO_SIGNAL;
    } finally {
      clearTimeout(timer);
    }
  }

  private isExpedited(tenantId: string, signal: ReadonlyMap<string, string>): boolean {
    const value = signal.get(tenantId);
    if (value === undefined || value === this.signalAtPassStart.get(tenantId)) return false;
    const now = this.now();
    const lastAt = this.lastExpeditedAt.get(tenantId);
    if (lastAt !== undefined && now < lastAt + TENANT_RUNNER_EXPEDITE_GAP_MS) return false;
    this.lastExpeditedAt.set(tenantId, now);
    return true;
  }

  private compareTenants(a: TTenant, b: TTenant): number {
    if (a.tenantId === b.tenantId) return 0;
    return a.tenantId < b.tenantId ? -1 : 1;
  }

  private forgetRemoved(tenants: readonly TTenant[]): void {
    const assigned = new Set(tenants.map((tenant) => tenant.tenantId));
    const tracked = [this.nextDue, this.failedPasses, this.signalAtPassStart, this.lastExpeditedAt];
    for (const book of tracked) {
      for (const tenantId of book.keys()) {
        if (!assigned.has(tenantId)) book.delete(tenantId);
      }
    }
  }

  private isDue(tenantId: string): boolean {
    const due = this.nextDue.get(tenantId);
    return due === undefined || this.now() >= due;
  }

  private async passTenant(tenant: TTenant, signal: ReadonlyMap<string, string>): Promise<void> {
    const { tenantId } = tenant;
    const { events } = this.deps;
    this.recordSignal(tenantId, signal.get(tenantId));
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

  private recordSignal(tenantId: string, value: string | undefined): void {
    if (value === undefined) this.signalAtPassStart.delete(tenantId);
    else this.signalAtPassStart.set(tenantId, value);
  }

  private schedule(tenantId: string, result: PassResult): void {
    this.nextDue.set(tenantId, this.now() + this.delayAfter(tenantId, result));
  }

  // Only a thrown pass advances the exponential counter: a skip or an unsettled outcome is not a fault.
  private delayAfter(tenantId: string, result: PassResult): number {
    const refreshMs = this.deps.intervals?.refreshMs ?? TENANT_RUNNER_REFRESH_MS;
    const retryMs = this.deps.intervals?.retryMs ?? TENANT_RUNNER_RETRY_MS;
    if (result === 'settled') {
      this.failedPasses.delete(tenantId);
      return refreshMs;
    }
    if (result === 'retry') return retryMs;
    const passes = (this.failedPasses.get(tenantId) ?? 0) + 1;
    this.failedPasses.set(tenantId, passes);
    const { backoff } = this.deps;
    if (!backoff) return retryMs;
    return Math.min(retryMs * 2 ** (passes - 1), backoff.maxMs);
  }
}
