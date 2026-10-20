import type { RoutingParameterReader, RoutingParameterValue } from './AwsRoutingParameterReader.js';
import {
  RoutingTableRefusalError,
  type RoutingTableVerifier,
  type VerifiedRoutingTable,
} from './RoutingTableVerifier.js';
import { ROUTING_TABLE_EXPIRY_WARNING_MS, ROUTING_TABLE_REQUIRED } from './routing-table-policy.js';

export const ROUTING_TABLE_REFRESH_MS = 300_000;

const ALARM_READ_FAILED = 'inference_routing_table_read_failed';
const ALARM_ABSENT = 'inference_routing_table_absent';
const ALARM_EXPIRED_IN_USE = 'inference_routing_table_expired_in_use';
const ALARM_EXPIRING = 'inference_routing_table_expiring';

export interface RoutingTableSource {
  current(): VerifiedRoutingTable | undefined;
  alarm(code: string): void;
}

export interface RoutingTableRefresherDeps {
  readonly onAlarm: (code: string) => void;
  readonly onApplied: (version: number) => void;
  readonly now?: () => number;
}

interface Installed {
  readonly verifier: RoutingTableVerifier;
  readonly reader: RoutingParameterReader;
}

export class RoutingTableRefresher implements RoutingTableSource {
  private installed: Installed | undefined;
  private applied: VerifiedRoutingTable | undefined;
  private appliedRaw: string | undefined;
  private inFlight: Promise<void> | undefined;
  private timer: NodeJS.Timeout | undefined;

  constructor(private readonly deps: RoutingTableRefresherDeps) {}

  // A table past its validity stops routing, whatever its version still guards.
  current(): VerifiedRoutingTable | undefined {
    if (this.applied === undefined || this.expired(this.applied)) return undefined;
    return this.applied;
  }

  alarm(code: string): void {
    this.deps.onAlarm(code);
  }

  install(verifier: RoutingTableVerifier, reader: RoutingParameterReader): void {
    if (this.installed !== undefined) throw new Error('routing_table_refresher_installed');
    this.installed = { verifier, reader };
  }

  refreshOnce(): Promise<void> {
    if (this.installed === undefined) return Promise.resolve();
    this.inFlight ??= this.refresh(this.installed).finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  start(intervalMs: number = ROUTING_TABLE_REFRESH_MS): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => void this.refreshOnce(), intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
  }

  private async refresh(installed: Installed): Promise<void> {
    try {
      const read = await installed.reader.read();
      if (read === 'absent') this.onAbsent();
      else await this.apply(installed.verifier, read);
    } catch {
      this.deps.onAlarm(ALARM_READ_FAILED);
    }
    this.alarmOnExpiry();
  }

  private onAbsent(): void {
    if (this.applied !== undefined || ROUTING_TABLE_REQUIRED) this.deps.onAlarm(ALARM_ABSENT);
  }

  private async apply(verifier: RoutingTableVerifier, read: RoutingParameterValue): Promise<void> {
    if (this.applied !== undefined && read.value === this.appliedRaw) return;
    try {
      const verified = await verifier.verify(read, this.applied?.table.version ?? 0);
      this.applied = verified;
      this.appliedRaw = read.value;
      this.deps.onApplied(verified.table.version);
    } catch (error) {
      this.deps.onAlarm(error instanceof RoutingTableRefusalError ? error.code : ALARM_READ_FAILED);
    }
  }

  private expired(verified: VerifiedRoutingTable): boolean {
    return verified.table.notAfterMs <= this.nowMs();
  }

  private nowMs(): number {
    return (this.deps.now ?? Date.now)();
  }

  private alarmOnExpiry(): void {
    if (this.applied === undefined) return;
    const remainingMs = this.applied.table.notAfterMs - this.nowMs();
    if (remainingMs <= 0) this.deps.onAlarm(ALARM_EXPIRED_IN_USE);
    else if (remainingMs <= ROUTING_TABLE_EXPIRY_WARNING_MS) this.deps.onAlarm(ALARM_EXPIRING);
  }
}
