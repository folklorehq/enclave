import { AsyncLocalStorage } from 'node:async_hooks';
import type { LlmOperationCache } from '../vector-cache.js';
import { BatchPendingError } from './batch-errors.js';
import type { ClaudeRequestBody } from './claude-request.js';

export interface PendingBatchRequest {
  readonly request: ClaudeRequestBody;
  readonly model: string;
  readonly purpose: string;
}

export interface BatchRunState {
  readonly orgId: string;
  readonly wikiRequestId: string;
  readonly pending: Map<string, PendingBatchRequest>;
  readonly store: LlmOperationCache;
  readonly nameKey: Buffer;
  readonly cacheSalt?: string;
  readonly drain?: boolean;
  /** A run that only collects: it may replay sealed results but never send a request of its own. */
  readonly collect?: boolean;
}

export class BatchRunScope {
  private readonly storage = new AsyncLocalStorage<BatchRunState>();
  private readonly refusedSends = new WeakSet<BatchRunState>();

  run<T>(state: BatchRunState, fn: () => Promise<T>): Promise<T> {
    return this.storage.run(state, fn);
  }

  current(): BatchRunState | undefined {
    return this.storage.getStore();
  }

  /** True for a miss's own error, and for any error raised while this run already holds a miss. */
  isPending(error?: unknown): boolean {
    if (error instanceof BatchPendingError) return true;
    const state = this.current();
    return state !== undefined && this.holdsMiss(state);
  }

  holdsMiss(state: BatchRunState): boolean {
    return state.pending.size > 0 || this.refusedSends.has(state);
  }

  /** Throws a miss in place of any provider call made from a run that only collects. */
  assertMaySpend(): void {
    const state = this.current();
    if (state?.collect !== true) return;
    this.refusedSends.add(state);
    throw new BatchPendingError();
  }

  assertNoMiss(): void {
    if (this.isPending()) throw new BatchPendingError();
  }

  /** Keeps a catch that swallows failures from also swallowing a batch miss. */
  rethrowIfPending(error: unknown): void {
    if (error instanceof BatchPendingError) throw error;
    this.assertNoMiss();
  }
}

export const batchRunScope = new BatchRunScope();
