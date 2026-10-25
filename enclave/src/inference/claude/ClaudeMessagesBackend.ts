import Anthropic from '@anthropic-ai/sdk';
import type { InferenceUsageSink, ToolSpec } from '@folklore/inference';
import type { CachedSystemPrefix } from '../InferencePurposeScope.js';
import { ANTHROPIC_ORIGIN } from '../../egress/anthropic-transport.js';
import { ClaudeRouteError } from './claude-route-errors.js';
import { claudeIdentityMismatch } from './ClaudeCredentialSource.js';
import { mapClaudeError, type ClaudeErrorContext } from './claude-error-map.js';
import {
  CHARS_PER_TOKEN_FLOOR,
  buildClaudeRequest,
  type ClaudeRequestInput,
} from './claude-request.js';
import type { AnthropicRoute } from './anthropic-route.js';

type CreatedMessage = Anthropic.Message;
type MessageEvents = AsyncIterable<Anthropic.RawMessageStreamEvent> & {
  controller: AbortController;
};

interface UsageCounts {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

interface StreamTally extends UsageCounts {
  started: boolean;
  stopped: boolean;
  stopReason: string | null;
  emittedChars: number;
  metered: boolean;
}

const SDK_LOG_LEVEL = 'off';
const NO_RETRIES = 0;
const END_TURNS: ReadonlySet<string> = new Set(['end_turn', 'stop_sequence']);

export interface ClaudeMessagesBackendDeps {
  readonly route: AnthropicRoute;
  readonly apiKey: string;
  readonly fetch: typeof globalThis.fetch;
  readonly timeoutMs: number;
  readonly expected: {
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
  };
  readonly usageSink: InferenceUsageSink;
  readonly errorContext: ClaudeErrorContext;
  readonly onIdentityMismatch: () => void;
  readonly cachedSystemPrefix?: CachedSystemPrefix;
}

/** One Messages call per operation, with the response bound to the compiled identity before it is used. */
export class ClaudeMessagesBackend {
  private readonly client: Anthropic;

  constructor(private readonly deps: ClaudeMessagesBackendDeps) {
    this.client = new Anthropic({
      apiKey: deps.apiKey,
      authToken: null,
      webhookKey: null,
      baseURL: ANTHROPIC_ORIGIN,
      fetch: deps.fetch,
      maxRetries: NO_RETRIES,
      logLevel: SDK_LOG_LEVEL,
      timeout: deps.timeoutMs,
    });
  }

  generate(prompt: string, systemPrompt?: string): Promise<string> {
    return this.text({ route: this.deps.route, prompt, systemPrompt }, 'generate');
  }

  critique(prompt: string, systemPrompt?: string): Promise<string> {
    return this.text({ route: this.deps.route, prompt, systemPrompt }, 'generate');
  }

  async *stream(
    prompt: string,
    systemPrompt: string | undefined,
    signal: AbortSignal,
  ): AsyncGenerator<string> {
    const tally = this.freshTally();
    try {
      const request = buildClaudeRequest({
        route: this.deps.route,
        prompt,
        systemPrompt,
        cachedSystemPrefix: this.deps.cachedSystemPrefix,
      });
      for await (const event of await this.openStream(request, signal)) {
        const text = this.absorb(event, tally);
        if (text === undefined) continue;
        tally.emittedChars += text.length;
        yield text;
      }
      if (tally.stopped) this.recordStreamUsage(tally);
      this.assertStreamStop(tally);
    } catch (error) {
      throw mapClaudeError(error, this.deps.errorContext);
    } finally {
      this.recordInterruptedStreamUsage(tally);
    }
  }

  async generateStructured(
    prompt: string,
    tool: ToolSpec,
    systemPrompt?: string,
  ): Promise<unknown> {
    const text = await this.text(
      { route: this.deps.route, prompt, systemPrompt, structured: tool },
      'structured',
    );
    return this.parsed(text);
  }

  private async text(
    input: Omit<ClaudeRequestInput, 'cachedSystemPrefix'>,
    operation: 'generate' | 'structured',
  ): Promise<string> {
    try {
      const request = buildClaudeRequest({
        ...input,
        cachedSystemPrefix: this.deps.cachedSystemPrefix,
      });
      const message = await this.send(request);
      this.recordUsage(message, operation);
      return this.completedText(message);
    } catch (error) {
      throw mapClaudeError(error, this.deps.errorContext);
    }
  }

  private async send(request: ReturnType<typeof buildClaudeRequest>): Promise<CreatedMessage> {
    const { data, response } = await this.client.messages
      .create(request as Anthropic.MessageCreateParamsNonStreaming)
      .withResponse();
    this.assertBound(response.headers);
    if (data.model !== this.deps.route.model) throw new ClaudeRouteError('claude_model_mismatch');
    return data;
  }

  private freshTally(): StreamTally {
    return {
      started: false,
      stopped: false,
      stopReason: null,
      emittedChars: 0,
      metered: false,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    };
  }

  private async openStream(
    request: ReturnType<typeof buildClaudeRequest>,
    signal: AbortSignal,
  ): Promise<MessageEvents> {
    const { data, response } = await this.client.messages
      .create({ ...request, stream: true } as Anthropic.MessageCreateParamsStreaming, { signal })
      .withResponse();
    try {
      this.assertBound(response.headers);
    } catch (error) {
      data.controller.abort();
      throw error;
    }
    return data;
  }

  private absorb(event: Anthropic.RawMessageStreamEvent, tally: StreamTally): string | undefined {
    if (event.type === 'message_start') {
      this.assertStreamModel(event.message.model);
      tally.started = true;
      tally.inputTokens = event.message.usage.input_tokens;
      tally.cacheReadTokens = event.message.usage.cache_read_input_tokens ?? 0;
      tally.cacheWriteTokens = event.message.usage.cache_creation_input_tokens ?? 0;
      return undefined;
    }
    if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
      if (!tally.started) throw new ClaudeRouteError('claude_upstream_error');
      return event.delta.text;
    }
    if (event.type === 'message_delta') {
      tally.stopReason = event.delta.stop_reason;
      tally.outputTokens = event.usage.output_tokens;
    }
    if (event.type === 'message_stop') tally.stopped = true;
    return undefined;
  }

  private assertStreamModel(model: string): void {
    if (model !== this.deps.route.model) throw new ClaudeRouteError('claude_model_mismatch');
  }

  private assertStreamStop(tally: StreamTally): void {
    if (tally.stopReason === 'refusal') throw new ClaudeRouteError('claude_refusal');
    if (tally.stopReason === 'max_tokens') throw new ClaudeRouteError('claude_output_truncated');
    if (!tally.stopped || tally.stopReason === null || !END_TURNS.has(tally.stopReason)) {
      throw new ClaudeRouteError('claude_upstream_error');
    }
    if (tally.emittedChars === 0) throw new ClaudeRouteError('claude_response_empty');
  }

  private recordStreamUsage(tally: StreamTally): void {
    this.reportUsage(tally, 'generate');
    tally.metered = true;
  }

  private recordInterruptedStreamUsage(tally: StreamTally): void {
    if (tally.metered || !tally.started) return;
    tally.metered = true;
    try {
      this.reportUsage(
        {
          ...tally,
          outputTokens: Math.ceil(tally.emittedChars / CHARS_PER_TOKEN_FLOOR),
        },
        'generate',
      );
    } catch {
      /* usage reporting must not mask the stream's own failure */
    }
  }

  private assertBound(headers: Pick<Headers, 'get'>): void {
    const mismatch = claudeIdentityMismatch(headers, this.deps.expected);
    if (mismatch === undefined) return;
    this.deps.onIdentityMismatch();
    throw new ClaudeRouteError(mismatch);
  }

  private recordUsage(message: CreatedMessage, operation: 'generate' | 'structured'): void {
    const { usage } = message;
    this.reportUsage(
      {
        inputTokens: usage.input_tokens,
        outputTokens: usage.output_tokens,
        cacheReadTokens: usage.cache_read_input_tokens ?? 0,
        cacheWriteTokens: usage.cache_creation_input_tokens ?? 0,
      },
      operation,
    );
  }

  private reportUsage(counts: UsageCounts, operation: 'generate' | 'structured'): void {
    const route = this.deps.route;
    this.deps.usageSink({
      model: route.model,
      operation,
      promptTokens: tokenCount(counts.inputTokens),
      completionTokens: tokenCount(counts.outputTokens),
      cached: false,
      purpose: route.untagged ? 'untagged' : route.purpose,
      outcome: route.arm === 'D' ? 'ok' : 'shadow',
      cacheReadTokens: tokenCount(counts.cacheReadTokens),
      cacheWriteTokens: tokenCount(counts.cacheWriteTokens),
    });
  }

  private completedText(message: CreatedMessage): string {
    if (message.stop_reason === 'refusal') throw new ClaudeRouteError('claude_refusal');
    if (message.stop_reason === 'max_tokens') throw new ClaudeRouteError('claude_output_truncated');
    if (message.stop_reason === null || !END_TURNS.has(message.stop_reason)) {
      throw new ClaudeRouteError('claude_upstream_error');
    }
    const text = message.content
      .flatMap((block) => (block.type === 'text' ? [block.text] : []))
      .join('');
    if (text.length === 0) throw new ClaudeRouteError('claude_response_empty');
    return text;
  }

  private parsed(text: string): unknown {
    try {
      return JSON.parse(text);
    } catch {
      throw mapClaudeError(
        new ClaudeRouteError('claude_structured_unparseable'),
        this.deps.errorContext,
      );
    }
  }
}

function tokenCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ClaudeRouteError('claude_usage_tokens_invalid');
  }
  return value;
}
