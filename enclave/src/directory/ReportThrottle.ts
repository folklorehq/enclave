import { TENANT_RUNNER_REFRESH_MS } from '../tenant/TenantPeriodicRunner.js';

// One report per refresh window carries the signal, however often or for however many tenants a pass fails.
export class ReportThrottle {
  private lastAdmittedAtMs: number | null = null;

  constructor(private readonly now: () => number) {}

  admit(): boolean {
    const nowMs = this.now();
    if (this.lastAdmittedAtMs !== null && nowMs - this.lastAdmittedAtMs < TENANT_RUNNER_REFRESH_MS)
      return false;
    this.lastAdmittedAtMs = nowMs;
    return true;
  }
}
