import { TelemetryEvent, type TelemetryClient } from '@folklore/telemetry';
import type { TeamProjectionRepositoryPort } from '@folklore/wiki';
import { TENANT_RUNNER_REFRESH_MS } from '../tenant/TenantPeriodicRunner.js';

const OPS_DISTINCT_ID = 'system';

// The enclave's logs have no production reader, so a failed team pass must leave on the check-in.
export class TeamProjectionFailureReporter {
  private lastReportedAtMs: number | null = null;

  constructor(
    private readonly telemetry: TelemetryClient,
    private readonly now: () => number,
  ) {}

  reporting(inner: TeamProjectionRepositoryPort): TeamProjectionRepositoryPort {
    return {
      reconcile: async (...args) => {
        try {
          return await inner.reconcile(...args);
        } catch (error) {
          this.report();
          throw error;
        }
      },
    };
  }

  private report(): void {
    const nowMs = this.now();
    if (this.lastReportedAtMs !== null && nowMs - this.lastReportedAtMs < TENANT_RUNNER_REFRESH_MS)
      return;
    this.lastReportedAtMs = nowMs;
    this.telemetry.track(TelemetryEvent.DirectoryTeamProjectionFailed, OPS_DISTINCT_ID, {});
  }
}
