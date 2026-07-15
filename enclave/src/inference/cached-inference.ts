import type { Cache } from '@folklore/core';
import { llmCacheKey } from './llm-cache.js';

// The embed/generate surface the enclave pipeline + synthesis workers depend on — the port the
// cache layers over, kept separate from the raw phala module so it can be injected and stubbed.
export interface InferenceModel {
  embed(text: string): Promise<number[]>;
  generate(prompt: string, systemPrompt?: string, temperature?: number): Promise<string>;
}

export interface CachedInferenceModels {
  embedModel: string;
  generateModel: string;
  // Bump when a prompt template changes so its cached outputs deterministically invalidate; model
  // ids already cover a model swap. Prompt text stays in the IP-excluded workers — only this tag rides.
  promptVersion: string;
}

// Bump on any prompt-template change across the enclave so its cached outputs invalidate together.
export const LLM_CACHE_PROMPT_VERSION = '1';

// generate() defaults temperature to 0 (determinism #2), so an unset temperature and an explicit 0
// must key identically or they would miss each other's cached greedy output.
const DEFAULT_TEMPERATURE = 0;

// Content-addressed replay + cost saver (determinism #1): same input → same output, no model call.
// Layered above the raw backend and injected, so the backend stays module-level and context-free.
export class CachedInference implements InferenceModel {
  constructor(
    private readonly backend: InferenceModel,
    private readonly cache: Cache,
    private readonly models: CachedInferenceModels,
  ) {}

  async embed(text: string): Promise<number[]> {
    const key = llmCacheKey(this.models.embedModel, this.models.promptVersion, text);
    const hit = await this.cache.get<string>(key);
    if (hit !== null) return JSON.parse(hit) as number[];
    const vector = await this.backend.embed(text);
    await this.cache.set(key, JSON.stringify(vector));
    return vector;
  }

  async generate(prompt: string, systemPrompt?: string, temperature?: number): Promise<string> {
    const canonical = JSON.stringify({
      prompt,
      systemPrompt: systemPrompt ?? null,
      temperature: temperature ?? DEFAULT_TEMPERATURE,
    });
    const key = llmCacheKey(this.models.generateModel, this.models.promptVersion, canonical);
    const hit = await this.cache.get<string>(key);
    if (hit !== null) return hit;
    const output = await this.backend.generate(prompt, systemPrompt, temperature);
    await this.cache.set(key, output);
    return output;
  }
}
