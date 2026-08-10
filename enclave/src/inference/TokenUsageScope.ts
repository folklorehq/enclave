import { AsyncLocalStorage } from 'node:async_hooks';
import type { InferenceUsageEvent, InferenceUsageSink } from '@folklore/inference';
import {
  TOKEN_USAGE_MODEL_MAX_LENGTH,
  TOKEN_USAGE_MODEL_PATTERN,
  type TokenUsage,
} from '@folklore/contracts/enclave';

// A model id that is not a plain identifier is not a model id — never forward it, or the one free
// string on the wire becomes a channel for customer text. Counted under a fixed label so the spend
// is still measured.
const UNKNOWN_MODEL = 'unknown';

// Excluded from the sanitized model-id charset, so two models can never collide on one key.
const KEY_SEPARATOR = '|';

/** Per-run token accounting for a process-wide inference backend: the sink resolves the caller's run through async context, so concurrent runs never pool their spend. */
export class TokenUsageScope {
  private readonly runs = new AsyncLocalStorage<Map<string, TokenUsage>>();

  // A failed run is still billed upstream and still retried, so its partial spend is handed to
  // `onPartial` rather than discarded — undercounting is the gap this instrumentation exists to close.
  async measure<T>(
    run: () => Promise<T>,
    onPartial?: (usage: TokenUsage[]) => void,
  ): Promise<{ result: T; usage: TokenUsage[] }> {
    const totals = new Map<string, TokenUsage>();
    try {
      const result = await this.runs.run(totals, run);
      return { result, usage: this.snapshot(totals) };
    } catch (err) {
      onPartial?.(this.snapshot(totals));
      throw err;
    }
  }

  record(event: InferenceUsageEvent): void {
    const totals = this.runs.getStore();
    if (!totals) return;
    const model = this.safeModel(event.model);
    const key = `${model}${KEY_SEPARATOR}${event.operation}`;
    const total = totals.get(key) ?? {
      model,
      operation: event.operation,
      calls: 0,
      cachedCalls: 0,
      promptTokens: 0,
      completionTokens: 0,
    };
    total.calls += 1;
    if (event.cached) total.cachedCalls += 1;
    total.promptTokens += event.promptTokens;
    total.completionTokens += event.completionTokens;
    totals.set(key, total);
  }

  private snapshot(totals: Map<string, TokenUsage>): TokenUsage[] {
    return [...totals.values()].map((total) => ({ ...total }));
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

export const recordTokenUsage: InferenceUsageSink = (event) => tokenUsageScope.record(event);
