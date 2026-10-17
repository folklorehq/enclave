export const PROMPT_TOKEN_WEIGHT = 0.02;
export const LATENCY_BUCKET_SAMPLES = 96;
export const LATENCY_RECENT_SAMPLES = 32;
export const LATENCY_BASELINE_MIN_SAMPLES = 32;
export const LATENCY_BASELINE_MAX_AGE_MS = 600_000;
export const LATENCY_SLOW_RATIO = 2;
export const LATENCY_HOLD_RATIO = 1.5;

export type PaceClass = 'normal' | 'hold' | 'slow';

interface PaceEntry {
  readonly pace: number;
  readonly at: number;
  readonly generation: number;
}

/** Compares each call shape's recent median pace with its own baseline median, so a naming call is never judged against a draft. */
export class UpstreamPaceTracker {
  private readonly buckets = new Map<number, PaceEntry[]>();
  private generation = 0;

  constructor(private readonly now: () => number = () => performance.now()) {}

  sample(requestMs: number, promptTokens: number, completionTokens: number): PaceClass {
    const units =
      completionTokens > 0 ? completionTokens + PROMPT_TOKEN_WEIGHT * promptTokens : promptTokens;
    const bucket = this.insert(Math.floor(Math.log2(Math.max(1, units))), {
      pace: requestMs / Math.max(1, units),
      at: this.now(),
      generation: this.generation,
    });
    return this.classify(bucket);
  }

  resetRecent(): void {
    this.generation += 1;
  }

  private insert(key: number, entry: PaceEntry): PaceEntry[] {
    const fresh = (this.buckets.get(key) ?? []).filter(
      (old) => entry.at - old.at <= LATENCY_BASELINE_MAX_AGE_MS,
    );
    fresh.push(entry);
    const kept = fresh.slice(-LATENCY_BUCKET_SAMPLES);
    this.buckets.set(key, kept);
    return kept;
  }

  private classify(bucket: readonly PaceEntry[]): PaceClass {
    const current = bucket.filter((entry) => entry.generation === this.generation);
    const recent = current.slice(-LATENCY_RECENT_SAMPLES);
    const baselineSize = bucket.length - recent.length;
    if (recent.length < LATENCY_RECENT_SAMPLES || baselineSize < LATENCY_BASELINE_MIN_SAMPLES) {
      return 'normal';
    }
    const recentSet = new Set(recent);
    const baseline = bucket.filter((entry) => !recentSet.has(entry));
    const ratio = this.median(recent) / this.median(baseline);
    if (ratio > LATENCY_SLOW_RATIO) return 'slow';
    return ratio > LATENCY_HOLD_RATIO ? 'hold' : 'normal';
  }

  private median(entries: readonly PaceEntry[]): number {
    const sorted = entries.map((entry) => entry.pace).sort((left, right) => left - right);
    const middle = Math.floor(sorted.length / 2);
    const upper = sorted[middle] ?? 0;
    return sorted.length % 2 === 1 ? upper : ((sorted[middle - 1] ?? 0) + upper) / 2;
  }
}
