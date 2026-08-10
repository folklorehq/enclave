import type { Cache } from '@folklore/core';
import type { InferenceOperation, InferenceUsageSink } from '@folklore/inference';
import { llmCacheKey } from './llm-cache.js';

// The embed/generate surface the enclave pipeline + synthesis workers depend on — the port the
// cache layers over, kept separate from the raw phala module so it can be injected and stubbed.
export interface InferenceModel {
  embed(text: string): Promise<number[]>;
  generate(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
  ): Promise<string>;
}

// The cross-family faithfulness critique. Separate from `InferenceModel` so the pipeline, which
// never critiques, is not made to carry it.
export interface CritiqueInference {
  critique(
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string>;
}

export type SynthesisInference = InferenceModel & CritiqueInference;

export interface CachedInferenceModels {
  embedModel: string;
  generateModel: string;
  critiqueModel: string;
  // Keys generate only. Bump when a caller's prompt or its accept-criteria change, so that caller's
  // cached outputs deterministically invalidate; model ids already cover a model swap.
  promptVersion: string;
}

// Shared by the callers whose prompt templates version together.
export const LLM_CACHE_PROMPT_VERSION = '1';

// Answers cached before the citation gate could be uncited, and this cache has no TTL, so replaying
// one would abstain forever; its own tag retires them without touching the templates above.
export const ANSWER_CACHE_VERSION = '2';

// Embedding input is raw text, never a prompt template, so it carries its own tag: a prompt bump
// must not purge every sealed embedding in the fleet and force a full re-embed.
const EMBED_CACHE_VERSION = '1';

// generate() defaults temperature to 0 (determinism #2), so an unset temperature and an explicit 0
// must key identically or they would miss each other's cached greedy output.
const DEFAULT_TEMPERATURE = 0;

// The one critique temperature: `generateCritique` sends it and this cache keys on it, or a
// critique would key against an output the backend never produced at that setting.
export const CRITIQUE_TEMPERATURE = 0;

// Content-addressed replay + cost saver (determinism #1): same input → same output, no model call.
// Layered above the raw backend and injected, so the backend stays module-level and context-free.
export class CachedInference implements SynthesisInference {
  constructor(
    private readonly backend: SynthesisInference,
    private readonly cache: Cache,
    private readonly models: CachedInferenceModels,
    private readonly usageSink?: InferenceUsageSink,
  ) {}

  async embed(text: string): Promise<number[]> {
    const key = llmCacheKey(this.models.embedModel, EMBED_CACHE_VERSION, text);
    const hit = await this.cache.get<string>(key);
    if (hit !== null) {
      this.recordCacheHit(this.models.embedModel, 'embed');
      return JSON.parse(hit) as number[];
    }
    const vector = await this.backend.embed(text);
    await this.cache.set(key, JSON.stringify(vector));
    return vector;
  }

  // A generation the caller rejects stays out of this TTL-less cache, so a retry is not a replay.
  async generate(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache: (output: string) => boolean = () => true,
  ): Promise<string> {
    const key = this.generationKey(this.models.generateModel, prompt, systemPrompt, temperature);
    return this.replayed(this.models.generateModel, 'generate', key, shouldCache, () =>
      this.backend.generate(prompt, systemPrompt, temperature),
    );
  }

  // Keyed on the critique model, never the drafter's: a redelivery must replay the same verdict the
  // published article was revised against, and the two models' entries must never collide. A reply
  // the caller cannot read stays out of this TTL-less cache, or it would pin the page forever.
  async critique(
    prompt: string,
    systemPrompt?: string,
    shouldCache: (output: string) => boolean = () => true,
  ): Promise<string> {
    const key = this.generationKey(
      this.models.critiqueModel,
      prompt,
      systemPrompt,
      CRITIQUE_TEMPERATURE,
    );
    // The wire's InferenceOperation enum has no 'critique' member — a critique call is a generate
    // call at the backend, so it is metered as 'generate' with the critique model id.
    return this.replayed(this.models.critiqueModel, 'generate', key, shouldCache, () =>
      this.backend.critique(prompt, systemPrompt),
    );
  }

  private generationKey(
    model: string,
    prompt: string,
    systemPrompt: string | undefined,
    temperature: number | undefined,
  ): string {
    const canonical = JSON.stringify({
      prompt,
      systemPrompt: systemPrompt ?? null,
      temperature: temperature ?? DEFAULT_TEMPERATURE,
    });
    return llmCacheKey(model, this.models.promptVersion, canonical);
  }

  private async replayed(
    model: string,
    operation: InferenceOperation,
    key: string,
    shouldCache: (output: string) => boolean,
    call: () => Promise<string>,
  ): Promise<string> {
    const hit = await this.cache.get<string>(key);
    if (hit !== null) {
      this.recordCacheHit(model, operation);
      return hit;
    }
    const output = await call();
    if (shouldCache(output)) await this.cache.set(key, output);
    return output;
  }

  // A replay is billed nothing, so it reports zero tokens; a miss stays silent because the backend
  // emits that call's real counts.
  private recordCacheHit(model: string, operation: InferenceOperation): void {
    try {
      this.usageSink?.({ model, operation, promptTokens: 0, completionTokens: 0, cached: true });
    } catch {
      // Deliberately silent — the error could quote a cached generation.
    }
  }
}
