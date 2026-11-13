import { MAX_RETRY_AFTER_MS } from '@folklore/inference';
import { parseRetryAfterMs } from '@folklore/utils';
import { TYPESAFE_ROOT_SET_MISMATCH } from '../../egress/typesafe-roots.js';
import {
  TYPESAFE_TLS_UNTRUSTED,
  TYPESAFE_UPSTREAM_TIMEOUT_CAUSE,
  typesafeTransportFailureOf,
} from '../../egress/typesafe-transport-failure.js';
import { discardBody } from '../bounded-response-body.js';
import { TypeSafeDecisionError } from './typesafe-decision-errors.js';

const HTTP_UNAUTHORIZED = 401;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_BAD_GATEWAY = 502;
const HTTP_SERVICE_UNAVAILABLE = 503;
const HTTP_GATEWAY_TIMEOUT = 504;
const HTTP_OVERLOADED = 529;
const SERVER_ERROR_FLOOR = 500;
const PERMANENT_REQUEST_STATUSES: ReadonlySet<number> = new Set([400, 413, 415, 422]);
const OVERLOADED_STATUSES: ReadonlySet<number> = new Set([
  HTTP_SERVICE_UNAVAILABLE,
  HTTP_OVERLOADED,
]);
const ALARM_CODES: ReadonlySet<string> = new Set([
  TYPESAFE_TLS_UNTRUSTED,
  TYPESAFE_ROOT_SET_MISMATCH,
]);

export interface TypeSafeErrorContext {
  readonly onCredentialRejected: () => void;
  readonly onAlarm?: (code: string) => void;
}

/** Names a thrown transport failure by code only, so no upstream text can reach the result. */
export function mapTypeSafeTransportError(
  error: unknown,
  context: Pick<TypeSafeErrorContext, 'onAlarm'>,
): TypeSafeDecisionError {
  if (error instanceof TypeSafeDecisionError) return error;
  const mapped = fromTransport(error);
  if (ALARM_CODES.has(mapped.code)) context.onAlarm?.(mapped.code);
  return mapped;
}

function fromTransport(error: unknown): TypeSafeDecisionError {
  const failure = typesafeTransportFailureOf(error);
  if (failure === TYPESAFE_TLS_UNTRUSTED)
    return new TypeSafeDecisionError('typesafe_tls_untrusted');
  if (failure === TYPESAFE_ROOT_SET_MISMATCH) {
    return new TypeSafeDecisionError('typesafe_tls_root_set_mismatch');
  }
  if (failure === TYPESAFE_UPSTREAM_TIMEOUT_CAUSE) {
    return new TypeSafeDecisionError('typesafe_timeout', HTTP_GATEWAY_TIMEOUT);
  }
  if (failure !== undefined) return new TypeSafeDecisionError('typesafe_request_refused');
  return new TypeSafeDecisionError('typesafe_unavailable', HTTP_BAD_GATEWAY);
}

/** Maps a non-2xx reply by status alone: the body is discarded unread. */
export async function mapTypeSafeStatus(
  response: Pick<Response, 'status' | 'headers' | 'body'>,
  context: TypeSafeErrorContext,
): Promise<TypeSafeDecisionError> {
  const { status } = response;
  await discardBody(response);
  if (status === HTTP_UNAUTHORIZED) {
    context.onCredentialRejected();
    return new TypeSafeDecisionError('typesafe_credential_rejected', status);
  }
  if (status === HTTP_TOO_MANY_REQUESTS) {
    const retryAfterMs = parseRetryAfterMs(
      response.headers.get('retry-after'),
      Date.now(),
      MAX_RETRY_AFTER_MS,
    );
    return new TypeSafeDecisionError('typesafe_rate_limited', status, false, retryAfterMs);
  }
  if (OVERLOADED_STATUSES.has(status))
    return new TypeSafeDecisionError('typesafe_overloaded', status);
  if (status >= SERVER_ERROR_FLOOR)
    return new TypeSafeDecisionError('typesafe_unavailable', status);
  return new TypeSafeDecisionError(
    'typesafe_request_invalid',
    status,
    PERMANENT_REQUEST_STATUSES.has(status),
  );
}
