import { monitorEventLoopDelay } from 'node:perf_hooks';
import type { Logger } from '@folklore/core';

export const EVENT_LOOP_DELAY_EVENT = 'event_loop_delay';

const DEFAULT_RESOLUTION_MS = 20;
const DEFAULT_REPORT_EVERY_MS = 60_000;
const NS_PER_MS = 1_000_000;
const MS_PER_SECOND = 1_000;
const TENTHS = 10;
const P50 = 50;
const P99 = 99;

export interface LoopDelayHistogram {
  enable(): boolean;
  disable(): boolean;
  reset(): void;
  percentile(percentile: number): number;
  readonly count: number;
  readonly max: number;
}

export interface LoopDelayTimer {
  stop(): void;
}

export interface EventLoopDelayMonitorOptions {
  histogram?: LoopDelayHistogram;
  resolutionMs?: number;
  reportEveryMs?: number;
  schedule?: (tick: () => void, everyMs: number) => LoopDelayTimer;
}

// Not yet wired to the ops-event relay: the control plane must accept the event name first, and the emitter must send at most one per 15 minutes (or on a threshold crossing), replacing any pending one.
/** Logs how late the event loop ran each window: numbers only, no tenant or content field. */
export class EventLoopDelayMonitor {
  private readonly histogram: LoopDelayHistogram;
  private readonly resolutionMs: number;
  private readonly reportEveryMs: number;
  private readonly schedule: (tick: () => void, everyMs: number) => LoopDelayTimer;
  private timer: LoopDelayTimer | undefined;

  constructor(
    private readonly logger: Logger,
    options: EventLoopDelayMonitorOptions = {},
  ) {
    this.resolutionMs = options.resolutionMs ?? DEFAULT_RESOLUTION_MS;
    this.reportEveryMs = options.reportEveryMs ?? DEFAULT_REPORT_EVERY_MS;
    this.histogram = options.histogram ?? monitorEventLoopDelay({ resolution: this.resolutionMs });
    this.schedule = options.schedule ?? ((tick, everyMs) => this.unrefTimer(tick, everyMs));
  }

  start(): void {
    if (this.timer) return;
    this.histogram.enable();
    this.timer = this.schedule(() => this.report(), this.reportEveryMs);
  }

  stop(): void {
    this.timer?.stop();
    this.timer = undefined;
    this.histogram.disable();
  }

  report(): void {
    if (this.histogram.count === 0) return;
    this.logger.info(EVENT_LOOP_DELAY_EVENT, {
      loopDelayP50Ms: this.delayMs(this.histogram.percentile(P50)),
      loopDelayP99Ms: this.delayMs(this.histogram.percentile(P99)),
      loopDelayMaxMs: this.delayMs(this.histogram.max),
      loopSamples: this.histogram.count,
      seconds: this.reportEveryMs / MS_PER_SECOND,
    });
    this.histogram.reset();
  }

  // The sampler records the whole timer period, so the period itself is not delay.
  private delayMs(nanoseconds: number): number {
    const lateMs = Math.max(0, nanoseconds / NS_PER_MS - this.resolutionMs);
    return Math.round(lateMs * TENTHS) / TENTHS;
  }

  private unrefTimer(tick: () => void, everyMs: number): LoopDelayTimer {
    const timer = setInterval(tick, everyMs);
    timer.unref();
    return { stop: () => clearInterval(timer) };
  }
}
