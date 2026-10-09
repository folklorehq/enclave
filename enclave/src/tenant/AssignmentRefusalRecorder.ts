import { contentFreeErrorType, isFailureCodeSlug, type Cache } from '@folklore/core';
import {
  assignmentRefusalSchema,
  poolAssignmentRefusalKey,
  type AssignmentRefusal,
} from '@folklore/contracts';

const UNNAMED_REFUSAL_CODE = 'assignment_refresh_failed';

/** Leaves a content-free reason for a refused pool manifest where the host agent can relay it. */
export class AssignmentRefusalRecorder {
  constructor(
    private readonly cache: Pick<Cache, 'set' | 'del'>,
    private readonly poolId: string,
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

  // A message is relayed only when it is already a guard slug; anything else may echo a value.
  private code(error: unknown): string {
    if (!(error instanceof Error)) return UNNAMED_REFUSAL_CODE;
    if (isFailureCodeSlug(error.message)) return error.message;
    const errorType = contentFreeErrorType(error);
    const named = errorType === null ? null : `${UNNAMED_REFUSAL_CODE}_${errorType}`;
    return isFailureCodeSlug(named) ? named : UNNAMED_REFUSAL_CODE;
  }
}
