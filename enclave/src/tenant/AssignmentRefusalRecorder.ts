import type { Cache } from '@folklore/core';
import {
  assignmentRefusalSchema,
  poolAssignmentRefusalKey,
  type AssignmentRefusal,
} from '@folklore/contracts';
import { errorClassCode, guardFailureCode } from '../boot/guard-failure-code.js';
import { isUnlistedRuntimeDatabaseCode } from '../runtime-database/runtime-database-failure-codes.js';

const UNNAMED_REFUSAL_CODE = 'assignment_refresh_failed';

/** Leaves a content-free reason for a refused pool manifest where the host agent can relay it. */
export class AssignmentRefusalRecorder {
  constructor(
    private readonly cache: Pick<Cache, 'set' | 'del'>,
    private readonly poolId: string,
    private readonly isPastBoot: () => boolean = () => false,
  ) {}

  async record(
    manifest: { readonly generation: number; readonly digest: string },
    error: unknown,
  ): Promise<void> {
    try {
      await this.cache.set(poolAssignmentRefusalKey(this.poolId), this.refusal(manifest, error));
    } catch {
      // Advisory only: a lost refusal must never turn a refused manifest into a crashed refresh.
    }
  }

  async clear(): Promise<void> {
    try {
      await this.cache.del(poolAssignmentRefusalKey(this.poolId));
    } catch {
      // A stale refusal names an older manifest, and the agent reads only an exact match.
    }
  }

  private refusal(
    manifest: { readonly generation: number; readonly digest: string },
    error: unknown,
  ): AssignmentRefusal {
    return assignmentRefusalSchema.parse({
      poolId: this.poolId,
      generation: manifest.generation,
      digest: manifest.digest,
      code: this.code(error),
    });
  }

  // Past boot the runtime database codes are closed, matching the boot status line.
  private code(error: unknown): string {
    const code = guardFailureCode(error, UNNAMED_REFUSAL_CODE);
    return this.isPastBoot() && isUnlistedRuntimeDatabaseCode(code)
      ? errorClassCode(error, UNNAMED_REFUSAL_CODE)
      : code;
  }
}
