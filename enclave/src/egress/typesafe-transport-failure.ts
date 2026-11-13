import { PINNED_UPSTREAM_TIMEOUT, pinnedTransportFailureOf } from './pinned-transport-failure.js';
import { TYPESAFE_ROOT_SET_MISMATCH } from './typesafe-roots.js';
import { TYPESAFE_REQUEST_REFUSED, TYPESAFE_TRANSPORT_CLOSED } from './typesafe-transport.js';

export const TYPESAFE_TLS_UNTRUSTED = 'typesafe_tls_untrusted';
export const TYPESAFE_UPSTREAM_TIMEOUT_CAUSE = PINNED_UPSTREAM_TIMEOUT;

export type TypeSafeTransportFailure =
  | typeof TYPESAFE_TLS_UNTRUSTED
  | typeof TYPESAFE_UPSTREAM_TIMEOUT_CAUSE
  | typeof TYPESAFE_REQUEST_REFUSED
  | typeof TYPESAFE_TRANSPORT_CLOSED
  | typeof TYPESAFE_ROOT_SET_MISMATCH;

const OWN_FAILURES: ReadonlySet<TypeSafeTransportFailure> = new Set([
  TYPESAFE_REQUEST_REFUSED,
  TYPESAFE_TRANSPORT_CLOSED,
  TYPESAFE_ROOT_SET_MISMATCH,
]);

export function typesafeTransportFailureOf(error: unknown): TypeSafeTransportFailure | undefined {
  return pinnedTransportFailureOf<TypeSafeTransportFailure>(error, {
    tlsUntrusted: TYPESAFE_TLS_UNTRUSTED,
    timeout: TYPESAFE_UPSTREAM_TIMEOUT_CAUSE,
    own: OWN_FAILURES,
  });
}
