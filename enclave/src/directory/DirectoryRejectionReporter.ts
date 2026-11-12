import { TelemetryEvent, type TelemetryClient } from '@folklore/telemetry';
import {
  DIRECTORY_ORG_MISMATCH,
  DIRECTORY_RESPONSE_INVALID,
} from './ControlPlaneTenantDirectorySource.js';
import { ReportThrottle } from './ReportThrottle.js';

const OPS_DISTINCT_ID = 'system';
const REFUSED_RESPONSE_CODES: ReadonlySet<string> = new Set([
  DIRECTORY_RESPONSE_INVALID,
  DIRECTORY_ORG_MISMATCH,
]);

// Only this runtime knows it refused the directory, and its logs have no production reader.
export class DirectoryRejectionReporter {
  private readonly throttle: ReportThrottle;

  constructor(
    private readonly telemetry: TelemetryClient,
    now: () => number,
  ) {
    this.throttle = new ReportThrottle(now);
  }

  observe(error: unknown): void {
    if (!this.isRefusal(error) || !this.throttle.admit()) return;
    this.telemetry.track(TelemetryEvent.DirectoryResponseRejected, OPS_DISTINCT_ID, {});
  }

  private isRefusal(error: unknown): boolean {
    return error instanceof Error && REFUSED_RESPONSE_CODES.has(error.message);
  }
}
