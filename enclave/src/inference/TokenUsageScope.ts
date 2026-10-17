import { AsyncLocalStorage } from 'node:async_hooks';
import type {
  InferenceCallLabel,
  InferenceTimer,
  InferenceUsageEvent,
  InferenceUsageSink,
} from '@folklore/inference';
import {
  TOKEN_USAGE_MODEL_MAX_LENGTH,
  TOKEN_USAGE_MODEL_PATTERN,
  type InferenceSpanPhase,
  type InferenceTimeline as InferenceTimelineWire,
  type InferenceTiming,
  type TokenUsage,
} from '@folklore/contracts/enclave';
import { InferenceTimeline, type SpanFailure } from './timing/InferenceTimeline.js';
import { reportUpstreamUsage } from './upstream-observation.js';

// A model id that is not a plain identifier is not a model id — never forward it, or the one free
// string on the wire becomes a channel for customer text. Counted under a fixed label so the spend
// is still measured.
const UNKNOWN_MODEL = 'unknown';

// Excluded from the sanitized model-id charset, so two models can never collide on one key.
const KEY_SEPARATOR = '|';

const OK = 'ok';

type TimedSum = 'trustedTimeMs' | 'bindMs' | 'requestMs' | 'responseMs' | 'verifyMs';
type TimedMax = 'trustedTimeMaxMs' | 'bindMaxMs' | 'requestMaxMs' | 'responseMaxMs' | 'verifyMaxMs';

// Session verification runs inside receipt verification, so only the outer phase is summed.
const AGGREGATED_PHASES: ReadonlyMap<InferenceSpanPhase, readonly [TimedSum, TimedMax]> = new Map([
  ['trusted_time', ['trustedTimeMs', 'trustedTimeMaxMs']],
  ['bind', ['bindMs', 'bindMaxMs']],
  ['request', ['requestMs', 'requestMaxMs']],
  ['response', ['responseMs', 'responseMaxMs']],
  ['attest', ['verifyMs', 'verifyMaxMs']],
  ['verify_receipt', ['verifyMs', 'verifyMaxMs']],
]);

export type SpanFailureClassifier = (error: unknown) => SpanFailure;

const UNCLASSIFIED: SpanFailureClassifier = () => ({ outcome: 'error_code' });

interface UsageRun {
  readonly totals: Map<string, TokenUsage>;
  readonly timeline: InferenceTimeline;
  readonly classify: SpanFailureClassifier;
}

export interface MeasuredRun<T> {
  result: T;
  usage: TokenUsage[];
  timeline: InferenceTimelineWire;
}

/** Per-run token and timing accounting for a process-wide inference backend: the sink resolves the caller's run through async context, so concurrent runs never pool their spend. */
export class TokenUsageScope {
  private readonly runs = new AsyncLocalStorage<UsageRun>();

  constructor(private readonly now: () => number = () => performance.now()) {}

  // A failed run is still billed upstream and still retried, so its partial spend is handed to
  // `onPartial` rather than discarded — undercounting is the gap this instrumentation exists to close.
  async measure<T>(
    run: () => Promise<T>,
    onPartial?: (usage: TokenUsage[]) => void,
    classify: SpanFailureClassifier = UNCLASSIFIED,
  ): Promise<MeasuredRun<T>> {
    const current: UsageRun = {
      totals: new Map(),
      timeline: new InferenceTimeline(this.now()),
      classify,
    };
    try {
      const result = await this.runs.run(current, run);
      return {
        result,
        usage: this.snapshot(current.totals),
        timeline: current.timeline.snapshot(),
      };
    } catch (err) {
      onPartial?.(this.snapshot(current.totals));
      throw err;
    }
  }

  record(event: InferenceUsageEvent): void {
    const current = this.runs.getStore();
    if (!current) return;
    const total = this.totalFor(current, this.safeModel(event.model), event.operation);
    total.calls += 1;
    if (event.cached) total.cachedCalls += 1;
    total.promptTokens += event.promptTokens;
    total.completionTokens += event.completionTokens;
  }

  /** Times one step of a provider call into the active run; outside a run the step runs untimed. */
  async time<T>(
    phase: InferenceSpanPhase,
    label: InferenceCallLabel,
    step: () => Promise<T>,
  ): Promise<T> {
    const current = this.runs.getStore();
    if (!current) return step();
    const startedAtMs = this.now();
    try {
      const value = await step();
      this.finish(current, phase, label, startedAtMs);
      return value;
    } catch (err) {
      this.finish(current, phase, label, startedAtMs, this.failure(current, err));
      throw err;
    }
  }

  async stage<T>(phase: InferenceSpanPhase, step: () => Promise<T>): Promise<T> {
    return this.time(phase, {}, step);
  }

  // Telemetry must never decide a call's outcome, so a recording fault is dropped silently.
  private finish(
    current: UsageRun,
    phase: InferenceSpanPhase,
    label: InferenceCallLabel,
    startedAtMs: number,
    failure?: SpanFailure,
  ): void {
    try {
      const endedAtMs = this.now();
      const model = label.model === undefined ? undefined : this.safeModel(label.model);
      const durationMs = current.timeline.add({
        phase,
        ...(model !== undefined ? { model } : {}),
        ...(label.role !== undefined ? { role: label.role } : {}),
        startedAtMs,
        endedAtMs,
        outcome: failure?.outcome ?? OK,
        ...(failure?.errorCode !== undefined ? { errorCode: failure.errorCode } : {}),
      });
      if (model !== undefined && label.operation !== undefined) {
        this.aggregate(current, model, label.operation, phase, durationMs);
      }
    } catch {
      /* timing is visibility only */
    }
  }

  private failure(current: UsageRun, error: unknown): SpanFailure {
    try {
      return current.classify(error);
    } catch {
      return UNCLASSIFIED(error);
    }
  }

  private aggregate(
    current: UsageRun,
    model: string,
    operation: TokenUsage['operation'],
    phase: InferenceSpanPhase,
    durationMs: number,
  ): void {
    const fields = AGGREGATED_PHASES.get(phase);
    if (!fields) return;
    const total = this.totalFor(current, model, operation);
    const timing = (total.timing ??= this.emptyTiming());
    const [sum, max] = fields;
    timing[sum] += durationMs;
    timing[max] = Math.max(timing[max], durationMs);
    if (phase === 'request') timing.calls += 1;
  }

  private totalFor(
    current: UsageRun,
    model: string,
    operation: TokenUsage['operation'],
  ): TokenUsage {
    const key = `${model}${KEY_SEPARATOR}${operation}`;
    const existing = current.totals.get(key);
    if (existing) return existing;
    const total: TokenUsage = {
      model,
      operation,
      calls: 0,
      cachedCalls: 0,
      promptTokens: 0,
      completionTokens: 0,
    };
    current.totals.set(key, total);
    return total;
  }

  private emptyTiming(): InferenceTiming {
    return {
      calls: 0,
      trustedTimeMs: 0,
      trustedTimeMaxMs: 0,
      bindMs: 0,
      bindMaxMs: 0,
      requestMs: 0,
      requestMaxMs: 0,
      responseMs: 0,
      responseMaxMs: 0,
      verifyMs: 0,
      verifyMaxMs: 0,
    };
  }

  private snapshot(totals: Map<string, TokenUsage>): TokenUsage[] {
    return [...totals.values()].map((total) =>
      total.timing ? { ...total, timing: { ...total.timing } } : { ...total },
    );
  }

  private safeModel(model: string): string {
    const conforms =
      model.length > 0 &&
      model.length <= TOKEN_USAGE_MODEL_MAX_LENGTH &&
      TOKEN_USAGE_MODEL_PATTERN.test(model);
    return conforms ? model : UNKNOWN_MODEL;
  }
}

// One scope per process: the phala backend is a module singleton, so its sink cannot be handed a
// per-call accumulator — it records into whichever run is active.
export const tokenUsageScope = new TokenUsageScope();

export const recordTokenUsage: InferenceUsageSink = (event) => {
  tokenUsageScope.record(event);
  reportUpstreamUsage(event.promptTokens, event.completionTokens);
};

export const timeInferenceStep: InferenceTimer = (phase, label, step) =>
  tokenUsageScope.time(phase, label, step);

export const timeSynthesisStage = <T>(phase: InferenceSpanPhase, step: () => Promise<T>) =>
  tokenUsageScope.stage(phase, step);
