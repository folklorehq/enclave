import { writeFileSync } from 'node:fs';
import type { EnclaveBootPhase } from '@folklore/control-plane';
import { errorClassCode, guardFailureCode } from './guard-failure-code.js';

// Lock-step with BOOT_STATUS_FILE in enclave/entrypoint.sh, which relays this line to the parent.
export const ENCLAVE_BOOT_STATUS_PATH = '/run/folklore-boot-status';
const BOOT_FAILED = 'boot_failed';
const RUNTIME_FAILED = 'runtime_failed';

interface FatalMonitorTarget {
  on(event: 'uncaughtExceptionMonitor', listener: (error: unknown) => void): unknown;
}

/** Leaves the boot phase and, on a crash, its guard code where the entrypoint relays them off-host. */
export class EnclaveBootStatus {
  private phase: EnclaveBootPhase = 'node_started';

  constructor(private readonly path: string = ENCLAVE_BOOT_STATUS_PATH) {}

  reach(phase: EnclaveBootPhase): void {
    this.phase = phase;
    this.record(`phase=${phase}`);
  }

  fail(error: unknown): void {
    this.record(`phase=${this.phase} fatal=${this.failureCode(error)}`);
  }

  installFatalMonitor(target: FatalMonitorTarget = process): void {
    target.on('uncaughtExceptionMonitor', (error) => this.fail(error));
  }

  // Past boot, a throw can come from a content path, where even a slug-shaped message may be a value.
  private failureCode(error: unknown): string {
    return this.phase === 'ready'
      ? errorClassCode(error, RUNTIME_FAILED)
      : guardFailureCode(error, BOOT_FAILED);
  }

  private record(line: string): void {
    try {
      writeFileSync(this.path, `${line}\n`);
    } catch {
      // Visibility only: a status write must never be the thing that stops a boot.
    }
  }
}
