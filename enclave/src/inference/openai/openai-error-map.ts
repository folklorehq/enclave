import { MAX_RETRY_AFTER_MS } from '@folklore/inference';
import { parseRetryAfterMs } from '@folklore/utils';
import { OPENAI_ROOT_SET_MISMATCH } from '../../egress/openai-roots.js';
import {
  OPENAI_TLS_UNTRUSTED,
  OPENAI_UPSTREAM_TIMEOUT_CAUSE,
  openaiTransportFailureOf,
} from '../../egress/openai-transport-failure.js';
import { OpenAIEmbedRouteError } from './openai-embed-errors.js';
import {
  OPENAI_ERROR_BODY_MAX_BYTES,
  discardBody,
  readBoundedText,
} from './openai-response-body.js';

const HTTP_BAD_REQUEST = 400;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_BAD_GATEWAY = 502;
const HTTP_GATEWAY_TIMEOUT = 504;
const MAX_CAUSE_DEPTH = 6;
const RETRYABLE_NETWORK_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'ETIMEDOUT',
  'EPIPE',
  'EAI_AGAIN',
  'UND_ERR_SOCKET',
  'UND_ERR_CLOSED',
  'ENOTFOUND',
]);
const SERVER_ERROR_FLOOR = 500;
const QUOTA_ERROR_CODES: ReadonlySet<string> = new Set([
  'insufficient_quota',
  'credit_balance_exhausted',
]);
const CONTEXT_LENGTH_CODE = 'context_length_exceeded';
const CONTEXT_LENGTH_PREFIX = "This model's maximum context length";
const ALARM_CODES: ReadonlySet<string> = new Set([OPENAI_TLS_UNTRUSTED, OPENAI_ROOT_SET_MISMATCH]);

export interface OpenAIErrorContext {
  readonly onCredentialRejected: () => void;
  readonly onAlarm?: (code: string) => void;
}

/** Names a thrown transport failure by code only, so no upstream text can reach the result. */
export function mapOpenAITransportError(
  error: unknown,
  context: Pick<OpenAIErrorContext, 'onAlarm'>,
): OpenAIEmbedRouteError {
  if (error instanceof OpenAIEmbedRouteError) return error;
  const mapped = fromTransport(error);
  if (ALARM_CODES.has(mapped.code)) context.onAlarm?.(mapped.code);
  return mapped;
}

function fromTransport(error: unknown): OpenAIEmbedRouteError {
  const failure = openaiTransportFailureOf(error);
  if (failure === OPENAI_TLS_UNTRUSTED) return new OpenAIEmbedRouteError('openai_tls_untrusted');
  if (failure === OPENAI_ROOT_SET_MISMATCH) {
    return new OpenAIEmbedRouteError('openai_tls_root_set_mismatch');
  }
  if (failure === OPENAI_UPSTREAM_TIMEOUT_CAUSE) {
    return new OpenAIEmbedRouteError('openai_overloaded', HTTP_GATEWAY_TIMEOUT);
  }
  if (failure !== undefined) return new OpenAIEmbedRouteError('openai_request_refused');
  return hasRetryableNetworkCode(error)
    ? new OpenAIEmbedRouteError('openai_overloaded', HTTP_BAD_GATEWAY)
    : new OpenAIEmbedRouteError('openai_request_refused');
}

function hasRetryableNetworkCode(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string' && RETRYABLE_NETWORK_CODES.has(code)) return true;
    current = current.cause;
  }
  return false;
}

/** Maps a non-2xx reply by status and by two matched error markers, never echoing the body. */
export async function mapOpenAIStatus(
  response: Pick<Response, 'status' | 'headers' | 'body'>,
  context: OpenAIErrorContext,
): Promise<OpenAIEmbedRouteError> {
  const { status } = response;
  if (status === HTTP_TOO_MANY_REQUESTS) return rateLimited(response);
  if (status === HTTP_BAD_REQUEST) return badRequest(response);
  await discardBody(response);
  if (status === HTTP_UNAUTHORIZED || status === HTTP_FORBIDDEN) {
    context.onCredentialRejected();
    return new OpenAIEmbedRouteError('openai_credential_rejected');
  }
  if (status >= SERVER_ERROR_FLOOR) return new OpenAIEmbedRouteError('openai_overloaded', status);
  return new OpenAIEmbedRouteError('openai_request_invalid');
}

async function rateLimited(
  response: Pick<Response, 'headers' | 'body'>,
): Promise<OpenAIEmbedRouteError> {
  const marker = await errorMarkers(response);
  if (marker.quota) return new OpenAIEmbedRouteError('openai_quota_exhausted');
  const retryAfterMs = parseRetryAfterMs(
    response.headers.get('retry-after'),
    Date.now(),
    MAX_RETRY_AFTER_MS,
  );
  return new OpenAIEmbedRouteError(
    'openai_rate_limited',
    HTTP_TOO_MANY_REQUESTS,
    false,
    retryAfterMs,
  );
}

async function badRequest(response: Pick<Response, 'body'>): Promise<OpenAIEmbedRouteError> {
  const marker = await errorMarkers(response);
  const tooLong = marker.code === CONTEXT_LENGTH_CODE || marker.messageStartsContext;
  return tooLong
    ? new OpenAIEmbedRouteError('openai_input_too_long', undefined, true)
    : new OpenAIEmbedRouteError('openai_request_invalid');
}

interface ErrorMarkers {
  readonly code: string | undefined;
  readonly quota: boolean;
  readonly messageStartsContext: boolean;
}

async function errorMarkers(response: Pick<Response, 'body'>): Promise<ErrorMarkers> {
  try {
    const parsed: unknown = JSON.parse(
      await readBoundedText(response, OPENAI_ERROR_BODY_MAX_BYTES),
    );
    const error = readObject(readObject(parsed)?.['error']);
    const code = error?.['code'];
    const type = error?.['type'];
    const message = error?.['message'];
    return {
      code: typeof code === 'string' ? code : undefined,
      quota:
        (typeof code === 'string' && QUOTA_ERROR_CODES.has(code)) ||
        (typeof type === 'string' && QUOTA_ERROR_CODES.has(type)),
      messageStartsContext:
        typeof message === 'string' && message.startsWith(CONTEXT_LENGTH_PREFIX),
    };
  } catch {
    return { code: undefined, quota: false, messageStartsContext: false };
  }
}

function readObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : undefined;
}
