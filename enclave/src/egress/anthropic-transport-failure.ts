import { ANTHROPIC_ROOT_SET_MISMATCH } from './anthropic-roots.js';
import { ANTHROPIC_REQUEST_REFUSED, ANTHROPIC_TRANSPORT_CLOSED } from './anthropic-transport.js';
import { PINNED_UPSTREAM_TIMEOUT, pinnedTransportFailureOf } from './pinned-transport-failure.js';

export const TLS_UNTRUSTED = 'claude_tls_untrusted';
export const UPSTREAM_TIMEOUT_CAUSE = PINNED_UPSTREAM_TIMEOUT;

export type TransportFailure =
  | typeof TLS_UNTRUSTED
  | typeof UPSTREAM_TIMEOUT_CAUSE
  | typeof ANTHROPIC_REQUEST_REFUSED
  | typeof ANTHROPIC_TRANSPORT_CLOSED
  | typeof ANTHROPIC_ROOT_SET_MISMATCH;

const OWN_FAILURES: ReadonlySet<TransportFailure> = new Set([
  ANTHROPIC_REQUEST_REFUSED,
  ANTHROPIC_TRANSPORT_CLOSED,
  ANTHROPIC_ROOT_SET_MISMATCH,
]);

export function transportFailureOf(error: unknown): TransportFailure | undefined {
  return pinnedTransportFailureOf<TransportFailure>(error, {
    tlsUntrusted: TLS_UNTRUSTED,
    timeout: UPSTREAM_TIMEOUT_CAUSE,
    own: OWN_FAILURES,
  });
}
