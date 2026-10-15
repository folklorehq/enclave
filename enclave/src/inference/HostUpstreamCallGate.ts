import type { UpstreamCallGate } from './TenantPolicyBoundInference.js';

export const HOST_UPSTREAM_CALLS = 10;
export const ORG_UPSTREAM_CALLS = 8;

export interface UpstreamCallLimits {
  readonly host: number;
  readonly perOrg: number;
}

const DEFAULT_LIMITS: UpstreamCallLimits = {
  host: HOST_UPSTREAM_CALLS,
  perOrg: ORG_UPSTREAM_CALLS,
};
const NEVER_ADMITTED = -1;

/** Bounds a host's in-flight upstream calls and one tenant's share, admitting waiting tenants in rotation. */
export class HostUpstreamCallGate implements UpstreamCallGate {
  private readonly activeByTenant = new Map<string, number>();
  private readonly waitingByTenant = new Map<string, Array<() => void>>();
  private readonly lastAdmittedAt = new Map<string, number>();
  private active = 0;
  private admissions = 0;

  constructor(private readonly limits: UpstreamCallLimits = DEFAULT_LIMITS) {
    if (!this.isPositiveInteger(limits.host) || !this.isPositiveInteger(limits.perOrg)) {
      throw new RangeError('upstream_call_limits_invalid');
    }
  }

  async run<T>(tenantId: string, call: () => Promise<T>): Promise<T> {
    // Admission only resolves a promise, so the call runs in this caller's async context.
    await this.admit(tenantId);
    try {
      return await call();
    } finally {
      this.release(tenantId);
    }
  }

  get activeCount(): number {
    return this.active;
  }

  pendingCount(tenantId?: string): number {
    if (tenantId !== undefined) return this.waitingByTenant.get(tenantId)?.length ?? 0;
    let pending = 0;
    for (const waiters of this.waitingByTenant.values()) pending += waiters.length;
    return pending;
  }

  private admit(tenantId: string): Promise<void> {
    if (!this.waitingByTenant.has(tenantId) && this.hasRoomFor(tenantId)) {
      this.take(tenantId);
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      const waiters = this.waitingByTenant.get(tenantId) ?? [];
      waiters.push(resolve);
      this.waitingByTenant.set(tenantId, waiters);
    });
  }

  private release(tenantId: string): void {
    this.active -= 1;
    const remaining = (this.activeByTenant.get(tenantId) ?? 0) - 1;
    if (remaining > 0) this.activeByTenant.set(tenantId, remaining);
    else this.activeByTenant.delete(tenantId);
    this.admitWaiters();
    if (this.waitingByTenant.size === 0) this.forgetIdleTenants();
  }

  private admitWaiters(): void {
    while (this.active < this.limits.host) {
      const next = this.nextInRotation();
      if (next === undefined) return;
      const waiters = this.waitingByTenant.get(next) ?? [];
      const resolve = waiters.shift();
      if (waiters.length === 0) this.waitingByTenant.delete(next);
      this.take(next);
      resolve?.();
    }
  }

  // The waiting tenant admitted least recently goes next, so each waiting tenant gets a turn.
  private nextInRotation(): string | undefined {
    let next: string | undefined;
    let nextAdmittedAt = Number.POSITIVE_INFINITY;
    for (const tenantId of this.waitingByTenant.keys()) {
      if (!this.hasRoomFor(tenantId)) continue;
      const admittedAt = this.lastAdmittedAt.get(tenantId) ?? NEVER_ADMITTED;
      if (admittedAt < nextAdmittedAt) {
        next = tenantId;
        nextAdmittedAt = admittedAt;
      }
    }
    return next;
  }

  private take(tenantId: string): void {
    this.active += 1;
    this.activeByTenant.set(tenantId, (this.activeByTenant.get(tenantId) ?? 0) + 1);
    this.admissions += 1;
    this.lastAdmittedAt.set(tenantId, this.admissions);
  }

  private hasRoomFor(tenantId: string): boolean {
    return (
      this.active < this.limits.host &&
      (this.activeByTenant.get(tenantId) ?? 0) < this.limits.perOrg
    );
  }

  // With nobody waiting, an idle tenant's turn history orders no one, so it is dropped.
  private forgetIdleTenants(): void {
    for (const tenantId of this.lastAdmittedAt.keys()) {
      if (!this.activeByTenant.has(tenantId)) this.lastAdmittedAt.delete(tenantId);
    }
  }

  private isPositiveInteger(value: number): boolean {
    return Number.isSafeInteger(value) && value > 0;
  }
}
