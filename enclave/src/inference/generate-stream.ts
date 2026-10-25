import { ChunkQueue } from './ChunkQueue.js';
import type { InferenceModel } from './CachedInference.js';

export const STREAM_ABORTED_CODE = 'stream_aborted';

export interface GenerateStreamRequest {
  readonly prompt: string;
  readonly systemPrompt?: string;
  readonly signal: AbortSignal;
  readonly shouldCache: (output: string) => boolean;
}

/** Text deltas only; its producer has started when it returns; completes only after a verified clean finish. */
export interface StreamingInference {
  generateStream(request: GenerateStreamRequest): AsyncIterable<string>;
}

/** A failure after the first chunk left the enclave; never fallback-eligible. */
export class GenerationStreamInterruptedError extends Error {
  constructor(readonly code: string) {
    super('generation_stream_interrupted');
    this.name = 'GenerationStreamInterruptedError';
  }
}

// Not an async generator: its body would start after the caller's purpose scope returned.
export function streamOrBuffer(
  model: InferenceModel & Partial<StreamingInference>,
  request: GenerateStreamRequest,
): AsyncIterable<string> {
  if (model.generateStream !== undefined) return model.generateStream(request);
  const queue = new ChunkQueue<string>(() => undefined);
  void bufferInto(model, request, queue).then(
    () => queue.end(),
    (error: unknown) => queue.fail(error),
  );
  return queue;
}

/** A cache rule that refuses once the request is aborted, so nothing is written after a teardown. */
export function cacheWhileLive(request: GenerateStreamRequest): (output: string) => boolean {
  return (output) => !request.signal.aborted && request.shouldCache(output);
}

export function assertStreamLive(signal: AbortSignal): void {
  if (signal.aborted) throw new GenerationStreamInterruptedError(STREAM_ABORTED_CODE);
}

async function bufferInto(
  model: InferenceModel,
  request: GenerateStreamRequest,
  queue: ChunkQueue<string>,
): Promise<void> {
  assertStreamLive(request.signal);
  const output = await model.generate(
    request.prompt,
    request.systemPrompt,
    undefined,
    cacheWhileLive(request),
  );
  assertStreamLive(request.signal);
  queue.push(output);
}
