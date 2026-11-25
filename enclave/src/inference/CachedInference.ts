// The embed/generate surface the enclave pipeline + synthesis workers depend on, kept separate from
// the raw phala module so it can be injected and stubbed.
export interface InferenceModel {
  embed(text: string, signal?: AbortSignal): Promise<number[]>;
  generate(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
    signal?: AbortSignal,
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
