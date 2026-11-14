import { BATCH_RESULTS_IDLE_TIMEOUT_MS } from './batch-limits.js';
import type { BatchResultsRead } from './BatchApiClient.js';
import { ClaudeRouteError } from './claude-route-errors.js';

type CutBy = 'idle' | 'budget' | 'signal';
type Timer = ReturnType<typeof setTimeout>;
type ChunkRead = Awaited<ReturnType<ReadableStreamDefaultReader<Uint8Array>['read']>>;

type GuardedRead = Pick<BatchResultsRead, 'budgetMs' | 'signal' | 'onCut'>;

/** The time bounds of one results read: headers, idle between chunks, a total budget, and the caller's signal. */
export class BatchResultsGuard {
  private readonly controller = new AbortController();
  private wake: (() => void) | undefined;
  private cutBy: CutBy | undefined;
  private cutReported = false;
  private headersTimer: Timer | undefined;
  private idleTimer: Timer | undefined;
  private budgetTimer: Timer | undefined;

  constructor(
    private readonly bounds: GuardedRead,
    private readonly headersMs: number,
  ) {
    bounds.signal?.addEventListener('abort', this.onCallerAbort, { once: true });
  }

  get signal(): AbortSignal {
    return this.controller.signal;
  }

  awaitingHeaders(): void {
    this.headersTimer = setTimeout(() => this.controller.abort(), this.headersMs);
  }

  bodyStarted(): void {
    clearTimeout(this.headersTimer);
    this.budgetTimer = setTimeout(() => this.cut('budget'), this.bounds.budgetMs);
  }

  // The idle bound runs only while a chunk is awaited, so the caller's sealing time counts against the total and not the idle bound.
  async next(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<ChunkRead> {
    this.throwIfCut();
    this.idleTimer = setTimeout(() => this.cut('idle'), BATCH_RESULTS_IDLE_TIMEOUT_MS);
    const woken = new Promise<undefined>((resolve) => (this.wake = () => resolve(undefined)));
    let outcome: ChunkRead | undefined;
    try {
      outcome = await Promise.race([reader.read(), woken]);
    } catch {
      if (this.cutBy === undefined) throw new ClaudeRouteError('claude_batch_unavailable');
    } finally {
      clearTimeout(this.idleTimer);
      this.wake = undefined;
    }
    if (outcome !== undefined) return outcome;
    this.throwIfCut();
    throw new ClaudeRouteError('claude_batch_unavailable');
  }

  dispose(): void {
    clearTimeout(this.headersTimer);
    clearTimeout(this.idleTimer);
    clearTimeout(this.budgetTimer);
    this.bounds.signal?.removeEventListener('abort', this.onCallerAbort);
    this.controller.abort();
  }

  private readonly onCallerAbort = (): void => this.cut('signal');

  private cut(by: CutBy): void {
    this.cutBy ??= by;
    this.wake?.();
    this.controller.abort();
  }

  private throwIfCut(): void {
    if (this.cutBy === undefined) return;
    if (!this.cutReported) {
      this.cutReported = true;
      this.bounds.onCut?.();
    }
    if (this.cutBy === 'signal') throw this.bounds.signal?.reason;
    throw new ClaudeRouteError('claude_batch_unavailable');
  }
}
