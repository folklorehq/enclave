import Anthropic from '@anthropic-ai/sdk';
import type { InferenceUsageSink, ToolSpec } from '@folklore/inference';
import type { CachedSystemPrefix } from '../InferencePurposeScope.js';
import { ANTHROPIC_ORIGIN } from '../../egress/anthropic-transport.js';
import { ClaudeRouteError } from './claude-route-errors.js';
import { claudeIdentityMismatch } from './ClaudeCredentialSource.js';
import { mapClaudeError, type ClaudeErrorContext } from './claude-error-map.js';
import { buildClaudeRequest, type ClaudeRequestInput } from './claude-request.js';
import type { ClaudeRoute } from './InferenceRouteResolver.js';

type CreatedMessage = Anthropic.Message;

const SDK_LOG_LEVEL = 'off';
const NO_RETRIES = 0;
const END_TURNS: ReadonlySet<string> = new Set(['end_turn', 'stop_sequence']);

export interface ClaudeMessagesBackendDeps {
  readonly route: ClaudeRoute;
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

  private assertBound(headers: Pick<Headers, 'get'>): void {
    const mismatch = claudeIdentityMismatch(headers, this.deps.expected);
    if (mismatch === undefined) return;
    this.deps.onIdentityMismatch();
    throw new ClaudeRouteError(mismatch);
  }

  private recordUsage(message: CreatedMessage, operation: 'generate' | 'structured'): void {
    const { usage } = message;
    const route = this.deps.route;
    this.deps.usageSink({
      model: route.model,
      operation,
      promptTokens: tokenCount(usage.input_tokens),
      completionTokens: tokenCount(usage.output_tokens),
      cached: false,
      purpose: route.untagged ? 'untagged' : route.purpose,
      outcome: route.arm === 'D' ? 'ok' : 'shadow',
      cacheReadTokens: tokenCount(usage.cache_read_input_tokens ?? 0),
      cacheWriteTokens: tokenCount(usage.cache_creation_input_tokens ?? 0),
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
