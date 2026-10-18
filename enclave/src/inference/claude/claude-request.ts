import type { ClaudeEffort } from '@folklore/contracts';
import type { ToolSpec } from '@folklore/inference';
import type { CachedSystemPrefix } from '../InferencePurposeScope.js';
import { ClaudeRouteError } from './claude-route-errors.js';
import {
  CLAUDE_PURPOSE_LIMITS,
  CLAUDE_WRITING_PURPOSES,
  HAIKU_MAX_INPUT_TOKENS,
  claudeMaxTokens,
} from './claude-purpose-limits.js';
import { assertRegisteredSchema, closedOutputSchema } from './claude-structured-schemas.js';
import type { ClaudeRoute } from './InferenceRouteResolver.js';

const CLAUDE_INFERENCE_GEO = 'us';
const HAIKU_MODEL = 'claude-haiku-5-5';
const SONNET_MODEL = 'claude-sonnet-5-5';
const CHARS_PER_TOKEN_FLOOR = 3;

export const CLAUDE_REQUEST_TOO_LARGE = 'claude_request_too_large_for_model';

interface TextBlock {
  readonly type: 'text';
  readonly text: string;
  readonly cache_control?: { readonly type: 'ephemeral' };
}

export interface ClaudeRequestBody {
  readonly model: string;
  readonly max_tokens: number;
  readonly system?: string | TextBlock[];
  readonly messages: { role: 'user'; content: string }[];
  readonly output_config: {
    readonly effort: ClaudeEffort;
    readonly format?: { readonly type: 'json_schema'; readonly schema: Record<string, unknown> };
  };
  readonly inference_geo: typeof CLAUDE_INFERENCE_GEO;
  readonly thinking?: { readonly type: 'between_tools' };
}

export interface ClaudeRequestInput {
  readonly route: ClaudeRoute;
  readonly prompt: string;
  readonly systemPrompt?: string;
  readonly structured?: ToolSpec;
  readonly cachedSystemPrefix?: CachedSystemPrefix;
}

export function buildClaudeRequest(input: ClaudeRequestInput): ClaudeRequestBody {
  const { route } = input;
  const system = systemFor(input);
  if (!fitsModel(input)) throw new ClaudeRouteError(CLAUDE_REQUEST_TOO_LARGE);
  return {
    model: route.model,
    max_tokens: claudeMaxTokens(route.purpose, route.effort),
    ...(system === undefined ? {} : { system }),
    messages: [{ role: 'user', content: input.prompt }],
    output_config: {
      effort: route.effort,
      ...(input.structured === undefined ? {} : { format: formatFor(input.structured) }),
    },
    inference_geo: CLAUDE_INFERENCE_GEO,
    ...(offThinking(route) ? { thinking: { type: 'between_tools' as const } } : {}),
  };
}

function formatFor(tool: ToolSpec): NonNullable<ClaudeRequestBody['output_config']['format']> {
  assertRegisteredSchema(tool);
  return {
    type: 'json_schema',
    schema: closedOutputSchema(tool.parameters) as Record<string, unknown>,
  };
}

function offThinking(route: ClaudeRoute): boolean {
  return route.model === SONNET_MODEL && !CLAUDE_WRITING_PURPOSES.has(route.purpose);
}

function systemFor(input: ClaudeRequestInput): string | TextBlock[] | undefined {
  const prefix = markedPrefix(input);
  if (prefix === undefined) return input.systemPrompt;
  return [...prefix, ...(input.systemPrompt === undefined ? [] : [text(input.systemPrompt)])];
}

// One breakpoint closes the shared prefix, whose first block is the per-tenant salt.
function markedPrefix(input: ClaudeRequestInput): TextBlock[] | undefined {
  const prefix = input.cachedSystemPrefix;
  if (prefix === undefined || !CLAUDE_PURPOSE_LIMITS[input.route.purpose].cacheMark) {
    return undefined;
  }
  return [
    text(prefix.salt),
    text(prefix.rules),
    { ...text(prefix.facts), cache_control: { type: 'ephemeral' } },
  ];
}

function text(value: string): TextBlock {
  return { type: 'text', text: value };
}

export function fitsModel(input: ClaudeRequestInput): boolean {
  if (input.route.model !== HAIKU_MODEL) return true;
  const parts = [input.prompt, JSON.stringify(systemFor(input) ?? '')];
  const chars = parts.reduce((sum, part) => sum + part.length, 0);
  return Math.ceil(chars / CHARS_PER_TOKEN_FLOOR) <= HAIKU_MAX_INPUT_TOKENS;
}
