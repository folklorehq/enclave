import { writeFileSync } from 'node:fs';
import { isFailureCodeSlug } from '@folklore/core';
import type { EnclaveBootPhase } from '@folklore/control-plane';
import { ENCLAVE_BOOT_STATUS_PATH } from './boot-status-path.js';
import type { EnclaveBootStep } from './boot-steps.js';
import { isRuntimeDatabaseActivationFailureCode } from '../runtime-database/runtime-database-failure-codes.js';
import { errorClassCode, guardFailureCode } from './guard-failure-code.js';

const BOOT_FAILED = 'boot_failed';
const RUNTIME_FAILED = 'runtime_failed';
const STEP_FAILED_SUFFIX = '_failed';
const PROCESS_EXIT = 'process_exit';
const READY_PHASE: EnclaveBootPhase = 'ready';
const API_DEGRADED_FALLBACK = 'api_start_failed';
const CLEAN_EXIT_CODE = 0;
const MAX_EXIT_STATUS = 255;
// The parent sink reads at most nine digits, so the count holds there instead of growing past it.
const MAX_MESSAGE_FAILURE_COUNT = 999_999_999;
const MESSAGE_FAILURE_FALLBACK = 'message_unclassified';
const WITHHELD_SNAPSHOT_SUFFIX = '_active_policy_snapshot_unavailable';

interface FatalMonitorTarget {
  on(event: 'uncaughtExceptionMonitor', listener: (error: unknown) => void): unknown;
  on(event: 'exit', listener: (code: number) => void): unknown;
}

/** Leaves the boot phase and, on a crash, its guard code where the entrypoint relays them off-host. */
export class EnclaveBootStatus {
  private phase: EnclaveBootPhase = 'node_started';
  private step: EnclaveBootStep | undefined;
  private failed = false;
  private degradation: string | undefined;
  private crashLine: string | undefined;
  private lastMessageFailure: string | undefined;
  private messageFailures = 0;

  constructor(private readonly path: string = ENCLAVE_BOOT_STATUS_PATH) {}

  reach(phase: EnclaveBootPhase): void {
    this.phase = phase;
    this.step = undefined;
    this.recordPhase();
  }

  // The box API can fail while boot carries on, so its code rides every later phase line.
  degrade(error: unknown): void {
    if (this.failed) return;
    this.degradation = this.degradationCode(error);
    this.recordPhase();
  }

  recover(): void {
    if (this.failed || this.degradation === undefined) return;
    this.degradation = undefined;
    this.recordPhase();
  }

  // A failed message never stops the enclave; its code only rides the next status lines.
  recordMessageFailure(code: string): void {
    const named = isFailureCodeSlug(code) ? code : MESSAGE_FAILURE_FALLBACK;
    if (!this.isWithheldSnapshotEcho(named)) this.lastMessageFailure = named;
    this.messageFailures = Math.min(this.messageFailures + 1, MAX_MESSAGE_FAILURE_COUNT);
    if (this.crashLine === undefined) this.recordPhase();
    else this.record(this.crashLine);
  }

  isReady(): boolean {
    return this.phase === READY_PHASE;
  }

  // A background rejection that lands while a step runs is named by that step too.
  begin(step: EnclaveBootStep): void {
    this.step = step;
  }

  fail(error: unknown): void {
    this.failed = true;
    this.crashLine = `phase=${this.phase} fatal=${this.failureCode(error)}`;
    this.record(this.crashLine);
  }

  installFatalMonitor(target: FatalMonitorTarget = process): void {
    target.on('uncaughtExceptionMonitor', (error) => this.fail(error));
    target.on('exit', (code) => this.recordExit(code));
  }

  // An explicit process.exit raises no exception, so without this it left a phase and no code.
  private recordExit(code: number): void {
    if (this.failed || code === CLEAN_EXIT_CODE) return;
    const named = Number.isInteger(code) && code > 0 && code <= MAX_EXIT_STATUS;
    this.crashLine = `phase=${this.phase} fatal=${named ? `${PROCESS_EXIT}_${code}` : PROCESS_EXIT}`;
    this.record(this.crashLine);
  }

  // Past boot, a throw can come from a content path, where even a slug-shaped message may be a value.
  private failureCode(error: unknown): string {
    return this.isReady()
      ? errorClassCode(error, RUNTIME_FAILED)
      : guardFailureCode(
          error,
          this.step === undefined ? BOOT_FAILED : `${this.step}${STEP_FAILED_SUFFIX}`,
        );
  }

  // Past boot only a fixed runtime database code is relayed by message, matching failureCode.
  private degradationCode(error: unknown): string {
    if (!this.isReady()) return guardFailureCode(error, API_DEGRADED_FALLBACK);
    return error instanceof Error && isRuntimeDatabaseActivationFailureCode(error.message)
      ? error.message
      : errorClassCode(error, API_DEGRADED_FALLBACK);
  }

  // A failure that withholds the policy snapshot makes every later attempt fail this way too, so
  // that echo must not hide the code that caused it.
  private isWithheldSnapshotEcho(code: string): boolean {
    return this.lastMessageFailure !== undefined && code.endsWith(WITHHELD_SNAPSHOT_SUFFIX);
  }

  private messageFailureSuffix(): string {
    if (this.lastMessageFailure === undefined) return '';
    return ` last=${this.lastMessageFailure} n=${this.messageFailures}`;
  }

  private recordPhase(): void {
    const degraded = this.degradation === undefined ? '' : ` fatal=${this.degradation}`;
    this.record(`phase=${this.phase}${degraded}`);
  }

  private record(line: string): void {
    try {
      writeFileSync(this.path, `${line}${this.messageFailureSuffix()}\n`);
    } catch {
      // Visibility only: a status write must never be the thing that stops a boot.
    }
  }
}
