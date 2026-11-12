import { TelemetryEvent, type TelemetryClient } from '@folklore/telemetry';
import type { TeamProjectionRepositoryPort } from '@folklore/wiki';
import { ReportThrottle } from './ReportThrottle.js';

const OPS_DISTINCT_ID = 'system';

// The enclave's logs have no production reader, so a failed team pass must leave on the check-in.
export class TeamProjectionFailureReporter {
  private readonly throttle: ReportThrottle;

  constructor(
    private readonly telemetry: TelemetryClient,
    now: () => number,
  ) {
    this.throttle = new ReportThrottle(now);
  }

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
    if (!this.throttle.admit()) return;
    this.telemetry.track(TelemetryEvent.DirectoryTeamProjectionFailed, OPS_DISTINCT_ID, {});
  }
}
