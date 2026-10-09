import { writeFileSync } from 'node:fs';
import type { EnclaveBootPhase } from '@folklore/control-plane';
import { ENCLAVE_BOOT_STATUS_PATH } from './boot-status-path.js';

const STARTED_PHASE: EnclaveBootPhase = 'node_started';
const MODULE_LOAD_FAILED = 'module_load_failed';
const MODULE_LOAD_EXITED = 'module_load_exited';
const CLEAN_EXIT_CODE = 0;

// Node's own resolution codes only: a module's own `code` could carry anything.
const RESOLUTION_FAILURES: ReadonlyMap<string, string> = new Map([
  ['ERR_MODULE_NOT_FOUND', 'module_not_found'],
  ['MODULE_NOT_FOUND', 'module_not_found'],
  ['ERR_PACKAGE_PATH_NOT_EXPORTED', 'module_path_not_exported'],
  ['ERR_DLOPEN_FAILED', 'module_native_load_failed'],
  ['ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING', 'module_type_stripping_refused'],
  ['ERR_UNKNOWN_FILE_EXTENSION', 'module_unknown_extension'],
]);

// Matched by constructor, never by name, so a module-defined class cannot pass itself off as one.
const BUILTIN_ERROR_CLASSES: ReadonlyMap<unknown, string> = new Map<unknown, string>([
  [SyntaxError, 'syntaxerror'],
  [TypeError, 'typeerror'],
  [ReferenceError, 'referenceerror'],
  [RangeError, 'rangeerror'],
]);

interface ModuleLoadProcess {
  on(event: 'uncaughtExceptionMonitor', listener: (error: unknown) => void): unknown;
  on(event: 'exit', listener: (code: number) => void): unknown;
}

/** Names a failure to load the enclave's module graph, before EnclaveBootStatus can exist. */
export class ModuleLoadGuard {
  private watching = false;
  private failed = false;

  constructor(
    private readonly path: string = ENCLAVE_BOOT_STATUS_PATH,
    private readonly target: ModuleLoadProcess = process,
  ) {}

  install(): void {
    this.watching = true;
    this.target.on('uncaughtExceptionMonitor', (error) =>
      this.recordFailure(this.failureCode(error)),
    );
    this.target.on('exit', (code) => {
      if (code !== CLEAN_EXIT_CODE) this.recordFailure(MODULE_LOAD_EXITED);
    });
    this.record(`phase=${STARTED_PHASE}`);
  }

  release(): void {
    this.watching = false;
  }

  private recordFailure(code: string): void {
    if (!this.watching || this.failed) return;
    this.failed = true;
    this.record(`phase=${STARTED_PHASE} fatal=${code}`);
  }

  private failureCode(error: unknown): string {
    const resolution = RESOLUTION_FAILURES.get(this.nodeErrorCode(error));
    if (resolution !== undefined) return resolution;
    const errorClass =
      error instanceof Error ? BUILTIN_ERROR_CLASSES.get(error.constructor) : undefined;
    return errorClass === undefined ? MODULE_LOAD_FAILED : `${MODULE_LOAD_FAILED}_${errorClass}`;
  }

  private nodeErrorCode(error: unknown): string {
    if (typeof error !== 'object' || error === null || !('code' in error)) return '';
    return typeof error.code === 'string' ? error.code : '';
  }

  private record(line: string): void {
    try {
      writeFileSync(this.path, `${line}\n`);
    } catch {
      // Visibility only: a status write must never be the thing that stops a boot.
    }
  }
}
