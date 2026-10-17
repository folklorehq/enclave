import { AttestationTurnAbandoned, DEFAULT_REFRESH_TIMEOUT_MS } from './attestation-turn-base.js';
import { attestationTurnScope, type AttestationTurnScope } from './AttestationTurnScope.js';

export type AttestationKind = 'checkpoint' | 'sample';
export type AttestationTurn = <T>(kind: AttestationKind, step: () => Promise<T>) => Promise<T>;

// A normal turn that has waited this long starts next, so priority traffic cannot starve a checkpoint.
export const NSM_NORMAL_MAX_WAIT_MS = 1_000;
// A recurring condition is re-raised this often, so a newer message failure cannot hide it from the boot status.
export const NSM_ALARM_REPEAT_MS = 60_000;
export const NSM_TURN_REFRESH_TIMEOUT_CODE = 'nsm_turn_refresh_timeout';
export const NSM_TURN_HOLD_PRIOR_MS = 50;
export const NSM_TURN_HOLD_EWMA_WEIGHT = 0.1;
// The sample-window bound: a longer turn already failed its own window, so one stall cannot collapse the ceiling.
export const NSM_TURN_SAMPLE_MAX_MS = 1_000;
export const ATTESTATIONS_PER_REFRESH_READ = 2;
export const NSM_BUDGET_MARGIN_MS = 1_000;
export const NSM_CALL_BUDGET_MS = DEFAULT_REFRESH_TIMEOUT_MS - NSM_BUDGET_MARGIN_MS;
export const NSM_MIN_CALL_CEILING = 4;

export interface AttestationCapacity {
  /** In-flight calls host-wide that still leave a two-attestation refresh read inside its timeout. */
  callCeiling(): number;
}

export interface NsmAttestationTurnstileOptions {
  readonly scope?: AttestationTurnScope;
  readonly now?: () => number;
  /** A queued turn was skipped: on the first, then at most once per NSM_ALARM_REPEAT_MS. */
  readonly onQueuedTurnSkipped?: () => void;
  readonly priorTurnHoldMs?: number;
}

interface Waiter {
  readonly sequence: number;
  readonly enqueuedAt: number;
  readonly abandonedBy: () => AbortSignal | undefined;
  readonly grant: () => void;
  readonly reject: (error: unknown) => void;
}

/** One attestation at a time host-wide, so a sample window brackets only its own device call and verify. */
export class NsmAttestationTurnstile implements AttestationCapacity {
  private readonly scope: AttestationTurnScope;
  private readonly now: () => number;
  private readonly priorityQueue: Waiter[] = [];
  private readonly normalQueue: Waiter[] = [];
  private sequence = 0;
  private running = false;
  private handoffPending = false;
  private lastSkipReportAt: number | undefined;
  private lastTurnStartedAt: number | undefined;
  private sequenceAtLastEnd = 0;
  private meanHoldMs: number;

  constructor(private readonly options: NsmAttestationTurnstileOptions = {}) {
    this.scope = options.scope ?? attestationTurnScope;
    this.now = options.now ?? (() => performance.now());
    this.meanHoldMs = this.validPrior(options.priorTurnHoldMs ?? NSM_TURN_HOLD_PRIOR_MS);
  }

  private validPrior(priorTurnHoldMs: number): number {
    if (!Number.isFinite(priorTurnHoldMs) || priorTurnHoldMs <= 0) {
      throw new RangeError('attestation_turn_hold_prior_invalid');
    }
    return priorTurnHoldMs;
  }

  meanTurnHoldMs(): number {
    return this.meanHoldMs;
  }

  callCeiling(): number {
    const turns = ATTESTATIONS_PER_REFRESH_READ * this.meanHoldMs;
    return Math.max(NSM_MIN_CALL_CEILING, Math.floor(NSM_CALL_BUDGET_MS / turns));
  }

  get waiting(): number {
    return this.priorityQueue.length + this.normalQueue.length;
  }

  readonly run: AttestationTurn = async (kind, step) => {
    const context = this.scope.current();
    const abandonedBy = (): AbortSignal | undefined => {
      if (context.abandonRead?.aborted === true) return context.abandonRead;
      if (kind === 'sample' && context.abandonAttempt?.aborted === true) {
        return context.abandonAttempt;
      }
      return undefined;
    };
    const signal = abandonedBy();
    if (signal !== undefined) throw new AttestationTurnAbandoned(signal.reason);
    const priority = kind === 'sample' || context.priority === true;
    await this.waitForTurn(priority, abandonedBy);
    try {
      return await step();
    } finally {
      this.endTurn();
    }
  };

  private waitForTurn(
    priority: boolean,
    abandonedBy: () => AbortSignal | undefined,
  ): Promise<void> {
    return new Promise<void>((grant, reject) => {
      this.sequence += 1;
      const queue = priority ? this.priorityQueue : this.normalQueue;
      queue.push({
        sequence: this.sequence,
        enqueuedAt: this.now(),
        abandonedBy,
        grant,
        reject,
      });
      if (!this.running && !this.handoffPending) this.dispatch();
    });
  }

  private endTurn(): void {
    this.running = false;
    this.sequenceAtLastEnd = this.sequence;
    if (this.waiting === 0) return;
    this.handoffPending = true;
    setImmediate(() => {
      this.handoffPending = false;
      this.dispatch();
    });
  }

  private dispatch(): void {
    for (let waiter = this.pickNext(); waiter !== undefined; waiter = this.pickNext()) {
      const signal = waiter.abandonedBy();
      if (signal === undefined) {
        this.running = true;
        this.recordTurnStart(waiter);
        waiter.grant();
        return;
      }
      waiter.reject(new AttestationTurnAbandoned(signal.reason));
      this.reportSkip();
    }
  }

  // Only a turn already queued as the last one ended measures the device; an idle start measures nothing.
  private recordTurnStart(waiter: Waiter): void {
    const at = this.now();
    if (this.lastTurnStartedAt !== undefined && waiter.sequence <= this.sequenceAtLastEnd) {
      const sample = Math.min(at - this.lastTurnStartedAt, NSM_TURN_SAMPLE_MAX_MS);
      this.meanHoldMs =
        NSM_TURN_HOLD_EWMA_WEIGHT * sample + (1 - NSM_TURN_HOLD_EWMA_WEIGHT) * this.meanHoldMs;
    }
    this.lastTurnStartedAt = at;
  }

  private pickNext(): Waiter | undefined {
    const normalHead = this.normalQueue[0];
    const priorityHead = this.priorityQueue[0];
    const normalHasAged =
      normalHead !== undefined &&
      this.now() - normalHead.enqueuedAt >= NSM_NORMAL_MAX_WAIT_MS &&
      (priorityHead === undefined || normalHead.sequence < priorityHead.sequence);
    if (normalHasAged) return this.normalQueue.shift();
    return priorityHead === undefined ? this.normalQueue.shift() : this.priorityQueue.shift();
  }

  private reportSkip(): void {
    const at = this.now();
    if (this.lastSkipReportAt !== undefined && at - this.lastSkipReportAt < NSM_ALARM_REPEAT_MS) {
      return;
    }
    this.lastSkipReportAt = at;
    this.options.onQueuedTurnSkipped?.();
  }
}
