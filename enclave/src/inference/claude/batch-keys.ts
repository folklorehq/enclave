import { createHmac } from 'node:crypto';
import { canonicalJson } from '@folklore/utils';
import type { CreatedMessage } from './ClaudeMessagesBackend.js';
import type { ClaudeRequestBody } from './claude-request.js';
import { CLAUDE_REQUEST_INVALID } from './claude-route-errors.js';

export const BATCH_RESULT_NAMESPACE = 'batch:v1';
export const BATCH_RESULT_ERASED = '{}';
const CUSTOM_ID_LABEL = 'pg1';
const CUSTOM_ID_MAX_LENGTH = 64;

/** A keyed digest of the request under the org's name key, so the id carries no request text. */
export function customIdFor(nameKey: Buffer, request: ClaudeRequestBody): string {
  const canonical = canonicalJson(JSON.parse(JSON.stringify(request)));
  const digest = createHmac('sha256', nameKey).update(canonical).digest('hex');
  return `${CUSTOM_ID_LABEL}${digest}`.slice(0, CUSTOM_ID_MAX_LENGTH);
}

export function resultKeyFor(customId: string): string {
  return `${BATCH_RESULT_NAMESPACE}:${customId}`;
}

export const SEALED_FAILURE_CODES: ReadonlySet<string> = new Set([CLAUDE_REQUEST_INVALID]);

export type SealedResult =
  | { readonly kind: 'message'; readonly message: CreatedMessage }
  | { readonly kind: 'failure'; readonly code: string };

export function failureMarker(code: string): string {
  return JSON.stringify({ failure: code });
}

export function sealedResultOf(sealed: unknown): SealedResult | undefined {
  if (typeof sealed !== 'string') return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(sealed);
  } catch {
    return undefined;
  }
  if (isCreatedMessage(parsed)) return { kind: 'message', message: parsed };
  const code = (parsed as { failure?: unknown } | null)?.failure;
  return typeof code === 'string' && SEALED_FAILURE_CODES.has(code)
    ? { kind: 'failure', code }
    : undefined;
}

export function isCreatedMessage(value: unknown): value is CreatedMessage {
  if (typeof value !== 'object' || value === null) return false;
  const message = value as Partial<Record<keyof CreatedMessage, unknown>>;
  const usage = message.usage as Record<string, unknown> | undefined;
  return (
    message.type === 'message' &&
    typeof message.model === 'string' &&
    Array.isArray(message.content) &&
    typeof usage?.['input_tokens'] === 'number' &&
    typeof usage['output_tokens'] === 'number'
  );
}
