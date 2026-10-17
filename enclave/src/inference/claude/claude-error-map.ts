import { APIConnectionError, APIConnectionTimeoutError, APIError } from '@anthropic-ai/sdk';
import { parseRetryAfterMs } from '@folklore/utils';
import {
  MAX_PROVIDER_PAUSE_MS,
  reportUpstreamLimitReached,
  reportUpstreamTimeout,
} from '../upstream-observation.js';
import { ANTHROPIC_ROOT_SET_MISMATCH } from '../../egress/anthropic-roots.js';
import {
  TLS_UNTRUSTED,
  UPSTREAM_TIMEOUT_CAUSE,
  transportFailureOf,
} from '../../egress/anthropic-transport-failure.js';
import { ClaudeRouteError } from './claude-route-errors.js';
import {
  CLAUDE_DEFERRABLE_CODES,
  CLAUDE_OPERATION_DEADLINE,
  CLAUDE_UPSTREAM_TIMEOUT,
  claudeOutageScope,
} from './claude-outage-scope.js';

const HTTP_BAD_REQUEST = 400;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_BAD_GATEWAY = 502;
const HTTP_OVERLOADED_STATUSES: ReadonlySet<number> = new Set([502, 503, 504, 529]);
const MAX_RETRY_AFTER_MS = 60_000;
const SPEND_LIMIT_ERROR_CODE = 'enforced_spend_limit_reached';
const WORKSPACE_LIMIT_PREFIX = 'You have reached your specified';
const CLIENT_ERROR_FLOOR = 400;
const SERVER_ERROR_FLOOR = 500;

export interface ClaudeErrorContext {
  readonly upstream: string | undefined;
  readonly budgetExpired: () => boolean;
  readonly onCredentialRejected: () => void;
  readonly onAlarm?: (code: string) => void;
}

const RECORDED = new WeakSet<ClaudeRouteError>();
const ALARMED = new WeakSet<ClaudeRouteError>();
const ALARM_CODES: ReadonlySet<string> = new Set([TLS_UNTRUSTED, ANTHROPIC_ROOT_SET_MISMATCH]);

export function mapClaudeError(error: unknown, context: ClaudeErrorContext): ClaudeRouteError {
  const mapped = error instanceof ClaudeRouteError ? error : classify(error, context);
  raiseAlarm(mapped, context);
  recordOutage(mapped, context);
  return mapped;
}

function classify(error: unknown, context: ClaudeErrorContext): ClaudeRouteError {
  if (error instanceof APIConnectionError) return connectionFailure(error, context);
  if (error instanceof APIError) return fromStatus(error, context);
  return fromTransport(error, context) ?? new ClaudeRouteError('claude_upstream_error');
}

function fromTransport(error: unknown, context: ClaudeErrorContext): ClaudeRouteError | undefined {
  const failure = transportFailureOf(error);
  if (failure === undefined) return undefined;
  if (failure !== UPSTREAM_TIMEOUT_CAUSE) return new ClaudeRouteError(failure);
  if (context.budgetExpired()) return new ClaudeRouteError(CLAUDE_OPERATION_DEADLINE);
  reportUpstreamTimeout();
  return new ClaudeRouteError(CLAUDE_UPSTREAM_TIMEOUT);
}

// The SDK reports its own timeout and our budget abort alike, so the budget decides which it was.
function connectionFailure(
  error: APIConnectionError,
  context: ClaudeErrorContext,
): ClaudeRouteError {
  if (context.budgetExpired()) return new ClaudeRouteError(CLAUDE_OPERATION_DEADLINE);
  if (!(error instanceof APIConnectionTimeoutError)) {
    return (
      fromTransport(error, context) ??
      new ClaudeRouteError('claude_connection_failed', HTTP_BAD_GATEWAY)
    );
  }
  reportUpstreamTimeout();
  return new ClaudeRouteError(CLAUDE_UPSTREAM_TIMEOUT);
}

function fromStatus(error: APIError, context: ClaudeErrorContext): ClaudeRouteError {
  const status = typeof error.status === 'number' ? error.status : 0;
  if (status === HTTP_TOO_MANY_REQUESTS) return rateLimited(error);
  if (status === HTTP_BAD_REQUEST && isWorkspaceLimit(error))
    return limitReached('claude_workspace_spend_limit');
  if (status === HTTP_UNAUTHORIZED || status === HTTP_FORBIDDEN) {
    context.onCredentialRejected();
    return new ClaudeRouteError('claude_credential_rejected');
  }
  if (HTTP_OVERLOADED_STATUSES.has(status))
    return new ClaudeRouteError('claude_overloaded', status);
  if (status >= SERVER_ERROR_FLOOR) return new ClaudeRouteError('claude_upstream_error');
  return status >= CLIENT_ERROR_FLOOR
    ? new ClaudeRouteError('claude_request_invalid')
    : new ClaudeRouteError('claude_upstream_error');
}

function rateLimited(error: APIError): ClaudeRouteError {
  if (errorCodeOf(error) === SPEND_LIMIT_ERROR_CODE)
    return limitReached('claude_spend_limit_reached');
  const retryAfterMs = parseRetryAfterMs(
    error.headers?.get('retry-after') ?? null,
    Date.now(),
    MAX_RETRY_AFTER_MS,
  );
  return new ClaudeRouteError('claude_rate_limited', HTTP_TOO_MANY_REQUESTS, retryAfterMs);
}

function limitReached(code: string): ClaudeRouteError {
  reportUpstreamLimitReached(MAX_PROVIDER_PAUSE_MS);
  return new ClaudeRouteError(code);
}

function isWorkspaceLimit(error: APIError): boolean {
  const message = readPath(error.error, ['error', 'message']);
  return typeof message === 'string' && message.startsWith(WORKSPACE_LIMIT_PREFIX);
}

function errorCodeOf(error: APIError): unknown {
  return (
    readPath(error.error, ['error', 'details', 'error_code']) ??
    readPath(error.error, ['details', 'error_code'])
  );
}

function readPath(value: unknown, path: readonly string[]): unknown {
  let current: unknown = value;
  for (const key of path) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function raiseAlarm(error: ClaudeRouteError, context: ClaudeErrorContext): void {
  if (!ALARM_CODES.has(error.code) || ALARMED.has(error)) return;
  ALARMED.add(error);
  context.onAlarm?.(error.code);
}

function recordOutage(error: ClaudeRouteError, context: ClaudeErrorContext): void {
  if (RECORDED.has(error)) return;
  if (!CLAUDE_DEFERRABLE_CODES.has(error.code) && error.code !== CLAUDE_OPERATION_DEADLINE) return;
  RECORDED.add(error);
  claudeOutageScope.record({ code: error.code, upstream: context.upstream });
}
