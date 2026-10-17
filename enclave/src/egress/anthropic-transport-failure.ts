import { ANTHROPIC_ROOT_SET_MISMATCH } from './anthropic-roots.js';
import { ANTHROPIC_REQUEST_REFUSED, ANTHROPIC_TRANSPORT_CLOSED } from './anthropic-transport.js';

export const TLS_UNTRUSTED = 'claude_tls_untrusted';
export const UPSTREAM_TIMEOUT_CAUSE = 'upstream_timeout';

const TLS_VERIFY_CODE =
  /^(?:CERT_|UNABLE_TO_|ERR_TLS_CERT_|DEPTH_ZERO_SELF_SIGNED_CERT$|SELF_SIGNED_CERT_IN_CHAIN$)/;
const TIMEOUT_CODE = /^UND_ERR_(?:CONNECT|HEADERS|BODY)_TIMEOUT$/;
const NATIVE_TIMEOUT_NAME = 'TimeoutError';
const OWN_FAILURES: ReadonlySet<string> = new Set([
  ANTHROPIC_REQUEST_REFUSED,
  ANTHROPIC_TRANSPORT_CLOSED,
  ANTHROPIC_ROOT_SET_MISMATCH,
]);
const MAX_CAUSE_DEPTH = 6;

export type TransportFailure =
  | typeof TLS_UNTRUSTED
  | typeof UPSTREAM_TIMEOUT_CAUSE
  | typeof ANTHROPIC_REQUEST_REFUSED
  | typeof ANTHROPIC_TRANSPORT_CLOSED
  | typeof ANTHROPIC_ROOT_SET_MISMATCH;

/** Names a failure from error codes and our own slugs only, so no upstream text can reach the result. */
export function transportFailureOf(error: unknown): TransportFailure | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
    const named = nameOf(current);
    if (named !== undefined) return named;
    current = current.cause;
  }
  return undefined;
}

function nameOf(error: Error): TransportFailure | undefined {
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && TLS_VERIFY_CODE.test(code)) return TLS_UNTRUSTED;
  if (typeof code === 'string' && TIMEOUT_CODE.test(code)) return UPSTREAM_TIMEOUT_CAUSE;
  if (error.name === NATIVE_TIMEOUT_NAME) return UPSTREAM_TIMEOUT_CAUSE;
  return OWN_FAILURES.has(error.message) ? (error.message as TransportFailure) : undefined;
}
