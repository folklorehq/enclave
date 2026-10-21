import { OPENAI_ROOT_SET_MISMATCH } from './openai-roots.js';
import { OPENAI_REQUEST_REFUSED, OPENAI_TRANSPORT_CLOSED } from './openai-transport.js';
import { PINNED_UPSTREAM_TIMEOUT, pinnedTransportFailureOf } from './pinned-transport-failure.js';

export const OPENAI_TLS_UNTRUSTED = 'openai_tls_untrusted';
export const OPENAI_UPSTREAM_TIMEOUT_CAUSE = PINNED_UPSTREAM_TIMEOUT;

export type OpenAITransportFailure =
  | typeof OPENAI_TLS_UNTRUSTED
  | typeof OPENAI_UPSTREAM_TIMEOUT_CAUSE
  | typeof OPENAI_REQUEST_REFUSED
  | typeof OPENAI_TRANSPORT_CLOSED
  | typeof OPENAI_ROOT_SET_MISMATCH;

const OWN_FAILURES: ReadonlySet<OpenAITransportFailure> = new Set([
  OPENAI_REQUEST_REFUSED,
  OPENAI_TRANSPORT_CLOSED,
  OPENAI_ROOT_SET_MISMATCH,
]);

export function openaiTransportFailureOf(error: unknown): OpenAITransportFailure | undefined {
  return pinnedTransportFailureOf<OpenAITransportFailure>(error, {
    tlsUntrusted: OPENAI_TLS_UNTRUSTED,
    timeout: OPENAI_UPSTREAM_TIMEOUT_CAUSE,
    own: OWN_FAILURES,
  });
}
