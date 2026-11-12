import { isFailureCodeSlug } from '@folklore/core';

export const MANIFEST_RETRY_BACKOFF_ALARM = 'assignment_manifest_retry_backoff';

export interface ManifestRetryBackoffOptions {
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
  readonly now?: () => number;
}

export interface DeferredManifestRetry {
  readonly failures: number;
  readonly refusal: unknown;
}

interface FailedManifest {
  readonly generation: number;
  readonly digest: string | undefined;
  readonly failures: number;
  readonly deferredFailures: number;
  readonly freeRetryUsed: boolean;
  readonly retryAt: number;
  readonly refusal: unknown;
}

// Not an Error, so the refusal recorder and the refresh log classify it exactly as they classified the original.
const NON_ERROR_REFUSAL: unknown = Object.freeze({});

/** Spaces out retries of the one manifest whose apply last failed; any other manifest may apply at once. */
export class ManifestRetryBackoff {
  private failed: FailedManifest | undefined;
  private readonly now: () => number;

  constructor(private readonly options: ManifestRetryBackoffOptions) {
    this.now = options.now ?? (() => performance.now());
  }

  deferral(generation: number, digest: string | undefined): DeferredManifestRetry | undefined {
    const failed = this.failed;
    if (!failed || !this.isSameManifest(failed, generation, digest)) return undefined;
    if (this.now() >= failed.retryAt) return undefined;
    return { failures: failed.failures, refusal: failed.refusal };
  }

  // A tenant left closed by a rejected hook reopens only on the next apply, so its manifest's first failure retries at once.
  recordFailure(
    generation: number,
    digest: string | undefined,
    error: unknown,
    leftTenantClosed: boolean,
  ): void {
    const previous = this.sameManifestRecord(generation, digest);
    const freeRetry = leftTenantClosed && !previous?.freeRetryUsed;
    const deferredFailures = (previous?.deferredFailures ?? 0) + (freeRetry ? 0 : 1);
    this.failed = {
      generation,
      digest,
      failures: (previous?.failures ?? 0) + 1,
      deferredFailures,
      freeRetryUsed: freeRetry || (previous?.freeRetryUsed ?? false),
      retryAt: this.now() + (freeRetry ? 0 : this.delayFor(deferredFailures)),
      refusal: this.refusalFrom(error),
    };
  }

  // A late hook that failed leaves its tenant closed with nothing pending; the next refresh must re-quiesce it.
  claimFreeRetry(generation: number, digest: string | undefined): void {
    const failed = this.failed;
    if (!failed || failed.freeRetryUsed || !this.isSameManifest(failed, generation, digest)) return;
    this.failed = {
      ...failed,
      deferredFailures: Math.max(0, failed.deferredFailures - 1),
      freeRetryUsed: true,
      retryAt: this.now(),
    };
  }

  private sameManifestRecord(
    generation: number,
    digest: string | undefined,
  ): FailedManifest | undefined {
    const failed = this.failed;
    return failed && this.isSameManifest(failed, generation, digest) ? failed : undefined;
  }

  private isSameManifest(
    failed: FailedManifest,
    generation: number,
    digest: string | undefined,
  ): boolean {
    return failed.generation === generation && failed.digest === digest;
  }

  private delayFor(deferredFailures: number): number {
    const { baseDelayMs, maxDelayMs } = this.options;
    return Math.min(maxDelayMs, baseDelayMs * 2 ** (deferredFailures - 1));
  }

  // Keeps only the error's class name and a guard slug, so a repeated refusal reports the same code.
  private refusalFrom(error: unknown): unknown {
    if (!(error instanceof Error)) return NON_ERROR_REFUSAL;
    const refusal = new Error(isFailureCodeSlug(error.message) ? error.message : '');
    refusal.name = error.name;
    return refusal;
  }
}
