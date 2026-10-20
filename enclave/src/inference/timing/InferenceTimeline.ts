import {
  INFERENCE_SPAN_ERROR_CODE_MAX_LENGTH,
  INFERENCE_SPAN_ERROR_CODE_PATTERN,
  INFERENCE_TIMELINE_MAX_SPANS,
  type InferenceSpan,
  type InferenceSpanOutcome,
  type InferenceSpanPhase,
  type InferenceTimeline as InferenceTimelineWire,
} from '@folklore/contracts/enclave';
import { INFERENCE_MODEL_IDS } from '@folklore/contracts';
import type { InferenceModelRole } from '@folklore/inference';

// The id pattern admits any identifier-shaped string, so a span names only a reviewed model.
const NAMEABLE_MODELS: ReadonlySet<string> = new Set<string>(INFERENCE_MODEL_IDS);
const UNLISTED_MODEL = 'unknown';

export interface SpanFailure {
  readonly outcome: Exclude<InferenceSpanOutcome, 'ok'>;
  readonly errorCode?: string;
}

export interface FinishedSpan {
  readonly phase: InferenceSpanPhase;
  readonly model?: string;
  readonly role?: InferenceModelRole;
  readonly startedAtMs: number;
  readonly endedAtMs: number;
  readonly outcome: InferenceSpanOutcome;
  readonly errorCode?: string;
}

interface KeptSpan {
  readonly wire: Omit<InferenceSpan, 'seq'>;
  readonly startedAtMs: number;
  readonly elapsedMs: number;
  readonly finished: number;
}

/** One run's spans: the first spans to finish are kept up to the wire cap, the rest only counted. */
export class InferenceTimeline {
  private readonly spans: KeptSpan[] = [];
  private dropped = 0;

  constructor(private readonly originMs: number) {}

  /** Returns the span's whole-millisecond duration, which a dropped span still has. */
  add(span: FinishedSpan): number {
    const durationMs = this.wholeMs(span.endedAtMs - span.startedAtMs);
    if (this.spans.length >= INFERENCE_TIMELINE_MAX_SPANS) {
      this.dropped += 1;
      return durationMs;
    }
    const errorCode = this.fixedCode(span.errorCode);
    this.spans.push({
      wire: {
        phase: span.phase,
        ...(span.model !== undefined ? { model: this.nameableModel(span.model) } : {}),
        ...(span.role !== undefined ? { role: span.role } : {}),
        startOffsetMs: this.wholeMs(span.startedAtMs - this.originMs),
        durationMs,
        outcome: span.outcome,
        ...(errorCode !== undefined ? { errorCode } : {}),
      },
      startedAtMs: span.startedAtMs,
      elapsedMs: span.endedAtMs - span.startedAtMs,
      finished: this.spans.length,
    });
    return durationMs;
  }

  // Kept in finishing order; sent by unrounded start, an enclosing (longer or later-finishing) span first.
  snapshot(): InferenceTimelineWire {
    const ordered = [...this.spans].sort(
      (a, b) =>
        a.startedAtMs - b.startedAtMs || b.elapsedMs - a.elapsedMs || b.finished - a.finished,
    );
    return {
      spans: ordered.map((span, seq) => ({ seq, ...span.wire })),
      spansDropped: this.dropped,
    };
  }

  private fixedCode(code: string | undefined): string | undefined {
    return code !== undefined &&
      code.length <= INFERENCE_SPAN_ERROR_CODE_MAX_LENGTH &&
      INFERENCE_SPAN_ERROR_CODE_PATTERN.test(code)
      ? code
      : undefined;
  }

  private nameableModel(model: string): string {
    return NAMEABLE_MODELS.has(model) ? model : UNLISTED_MODEL;
  }

  private wholeMs(ms: number): number {
    return Number.isFinite(ms) && ms > 0 ? Math.min(Math.round(ms), Number.MAX_SAFE_INTEGER) : 0;
  }
}
