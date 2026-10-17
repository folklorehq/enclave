import { MAX_PROVIDER_PAUSE_MS } from './upstream-observation.js';

export interface AdaptiveWindowLimits {
  readonly initial: number;
  readonly floor: number;
  readonly ceiling: number;
}

export const UPSTREAM_WINDOW_LIMITS: AdaptiveWindowLimits = {
  initial: 10,
  floor: 2,
  ceiling: 64,
};
export const OVERLOAD_DECREASE_FACTOR = 0.5;
export const LATENCY_DECREASE_FACTOR = 0.8;
export const PAUSE_JITTER_FRACTION = 0.1;

/** One upstream's concurrency window: slow start, additive growth, one multiplicative decrease per epoch. */
export class AdaptiveUpstreamWindow {
  private window: number;
  private currentEpoch = 0;
  private slowStart = true;
  private pausedUntil = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly limits: AdaptiveWindowLimits = UPSTREAM_WINDOW_LIMITS,
    private readonly now: () => number = () => performance.now(),
    private readonly random: () => number = Math.random,
  ) {
    this.window = limits.initial;
  }

  get limit(): number {
    return Math.min(this.limits.ceiling, Math.max(this.limits.floor, Math.floor(this.window)));
  }

  get epoch(): number {
    return this.currentEpoch;
  }

  served(grow: boolean): void {
    if (!grow) return;
    this.window = Math.min(
      this.limits.ceiling,
      this.window + (this.slowStart ? 1 : 1 / this.window),
    );
  }

  overloaded(admittedAtEpoch: number, pauseMs: number | undefined): boolean {
    if (pauseMs !== undefined) this.throttled(pauseMs);
    return this.decrease(admittedAtEpoch, OVERLOAD_DECREASE_FACTOR);
  }

  slowed(admittedAtEpoch: number): boolean {
    return this.decrease(admittedAtEpoch, LATENCY_DECREASE_FACTOR);
  }

  throttled(pauseMs: number): void {
    const clamped = Math.min(pauseMs, MAX_PROVIDER_PAUSE_MS);
    if (!(clamped > 0)) return;
    const jitter = Math.floor(this.random() * PAUSE_JITTER_FRACTION * clamped);
    this.pausedUntil = Math.max(this.pausedUntil, this.now() + clamped + jitter);
  }

  pauseRemainingMs(): number {
    return Math.max(0, this.pausedUntil - this.now());
  }

  private decrease(admittedAtEpoch: number, factor: number): boolean {
    if (admittedAtEpoch !== this.currentEpoch) return false;
    this.window = Math.max(this.limits.floor, this.window * factor);
    this.currentEpoch += 1;
    this.slowStart = false;
    return true;
  }
}
