import type { InferenceUsageSink } from '@folklore/inference';
import { z } from 'zod';
import { OPENAI_EMBEDDINGS_PATH, OPENAI_ORIGIN } from '../../egress/openai-transport.js';
import { SHORT_OPERATION_LIMITS } from '../public-aci-operation-limits.js';
import { OpenAIEmbedRouteError } from './openai-embed-errors.js';
import type { OpenAIEmbedRouteIdentity } from './openai-embed-route-config.js';
import { OPENAI_EMBED_DIMENSIONS, OPENAI_EMBED_MODEL } from './openai-embed-route-state.js';
import { mapOpenAIStatus, mapOpenAITransportError } from './openai-error-map.js';
import { OPENAI_EMBED_MAX_INPUT_BYTES, clipUtf8 } from './openai-input-clip.js';
import { OPENAI_SUCCESS_BODY_MAX_BYTES, readBoundedText } from './openai-response-body.js';
import { openaiIdentityMismatch, type OpenAICredentialSource } from './OpenAICredentialSource.js';

export const OPENAI_EMBED_REQUEST_TIMEOUT_MS = SHORT_OPERATION_LIMITS.requestTimeoutMs;

const USER_AGENT = 'folklore-enclave';
const DATED_MODEL_PREFIX = `${OPENAI_EMBED_MODEL}-`;

const embeddingsResponseSchema = z
  .object({
    data: z.array(z.object({ embedding: z.array(z.number()), index: z.number().int() }).strip()),
    model: z.string(),
    usage: z.object({ prompt_tokens: z.number().int().nonnegative() }).strip(),
  })
  .strip();

type EmbeddingsResponse = z.infer<typeof embeddingsResponseSchema>;

export interface OpenAIEmbeddingsBackendDeps {
  readonly fetch: typeof globalThis.fetch;
  readonly credentials: Pick<OpenAICredentialSource, 'key' | 'invalidate'>;
  readonly identity: OpenAIEmbedRouteIdentity;
  readonly usageSink?: InferenceUsageSink;
  readonly onAlarm?: (code: string) => void;
}

/** One embeddings call per text, with each response bound to the compiled identity before it is used. */
export class OpenAIEmbeddingsBackend {
  constructor(private readonly deps: OpenAIEmbeddingsBackendDeps) {}

  async embed(text: string): Promise<number[]> {
    const input = this.clippedInput(text);
    try {
      const key = await this.deps.credentials.key();
      return await this.vectorFrom(await this.post(input, key));
    } catch (error) {
      throw mapOpenAITransportError(error, this.alarm());
    }
  }

  private clippedInput(text: string): string {
    const input = clipUtf8(text, OPENAI_EMBED_MAX_INPUT_BYTES);
    if (input.trim() === '')
      throw new OpenAIEmbedRouteError('openai_embed_input_empty', undefined, true);
    return input;
  }

  private post(input: string, key: string): Promise<Response> {
    return this.deps.fetch(`${OPENAI_ORIGIN}${OPENAI_EMBEDDINGS_PATH}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${key}`,
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify({
        model: OPENAI_EMBED_MODEL,
        input,
        dimensions: OPENAI_EMBED_DIMENSIONS,
        encoding_format: 'float',
      }),
      signal: AbortSignal.timeout(OPENAI_EMBED_REQUEST_TIMEOUT_MS),
    });
  }

  private async vectorFrom(response: Response): Promise<number[]> {
    if (!response.ok) throw await this.statusFailure(response);
    this.assertBound(response.headers);
    const parsed = this.parsed(await this.boundedText(response));
    const vector = this.checkedVector(parsed);
    this.recordUsage(parsed.usage.prompt_tokens);
    return vector;
  }

  private statusFailure(response: Response): Promise<OpenAIEmbedRouteError> {
    return mapOpenAIStatus(response, {
      onCredentialRejected: () => this.deps.credentials.invalidate('rejected'),
      ...this.alarm(),
    });
  }

  private assertBound(headers: Pick<Headers, 'get'>): void {
    const mismatch = openaiIdentityMismatch(headers, this.deps.identity);
    if (mismatch === undefined) return;
    this.deps.credentials.invalidate('mismatch');
    throw new OpenAIEmbedRouteError(mismatch);
  }

  private boundedText(response: Response): Promise<string> {
    return readBoundedText(response, OPENAI_SUCCESS_BODY_MAX_BYTES).catch(() => {
      throw new OpenAIEmbedRouteError('openai_response_invalid');
    });
  }

  private parsed(text: string): EmbeddingsResponse {
    try {
      return embeddingsResponseSchema.parse(JSON.parse(text));
    } catch {
      throw new OpenAIEmbedRouteError('openai_response_invalid');
    }
  }

  private checkedVector(parsed: EmbeddingsResponse): number[] {
    const [row] = parsed.data;
    if (parsed.data.length !== 1 || row === undefined) {
      throw new OpenAIEmbedRouteError('openai_response_invalid');
    }
    if (parsed.model !== OPENAI_EMBED_MODEL && !parsed.model.startsWith(DATED_MODEL_PREFIX)) {
      throw new OpenAIEmbedRouteError('openai_model_mismatch');
    }
    if (row.embedding.length !== OPENAI_EMBED_DIMENSIONS) {
      throw new OpenAIEmbedRouteError('openai_embedding_dimension_mismatch');
    }
    if (!row.embedding.every(Number.isFinite)) {
      throw new OpenAIEmbedRouteError('openai_embedding_non_finite');
    }
    return row.embedding;
  }

  private recordUsage(promptTokens: number): void {
    this.deps.usageSink?.({
      model: OPENAI_EMBED_MODEL,
      operation: 'embed',
      promptTokens,
      completionTokens: 0,
      cached: false,
    });
  }

  private alarm(): { readonly onAlarm?: (code: string) => void } {
    const { onAlarm } = this.deps;
    return onAlarm === undefined ? {} : { onAlarm };
  }
}
