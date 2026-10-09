import { writeFileSync } from 'node:fs';
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

  isReady(): boolean {
    return this.phase === READY_PHASE;
  }

  // A background rejection that lands while a step runs is named by that step too.
  begin(step: EnclaveBootStep): void {
    this.step = step;
  }

  fail(error: unknown): void {
    this.failed = true;
    this.record(`phase=${this.phase} fatal=${this.failureCode(error)}`);
  }

  installFatalMonitor(target: FatalMonitorTarget = process): void {
    target.on('uncaughtExceptionMonitor', (error) => this.fail(error));
    target.on('exit', (code) => this.recordExit(code));
  }

  // An explicit process.exit raises no exception, so without this it left a phase and no code.
  private recordExit(code: number): void {
    if (this.failed || code === CLEAN_EXIT_CODE) return;
    const named = Number.isInteger(code) && code > 0 && code <= MAX_EXIT_STATUS;
    this.record(`phase=${this.phase} fatal=${named ? `${PROCESS_EXIT}_${code}` : PROCESS_EXIT}`);
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

  private recordPhase(): void {
    const degraded = this.degradation === undefined ? '' : ` fatal=${this.degradation}`;
    this.record(`phase=${this.phase}${degraded}`);
  }

  private record(line: string): void {
    try {
      writeFileSync(this.path, `${line}\n`);
    } catch {
      // Visibility only: a status write must never be the thing that stops a boot.
    }
  }
}
