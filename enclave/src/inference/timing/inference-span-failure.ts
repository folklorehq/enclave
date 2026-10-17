import { ProviderHttpError } from '@folklore/inference';
import { messageFailureCode } from '../../tenant/message-failure/message-failure-code.js';
import type { SpanFailure } from './InferenceTimeline.js';

const MAX_CAUSE_DEPTH = 8;
const HTTP_TOO_MANY_REQUESTS = 429;
const TIMEOUT_ERROR_NAMES: ReadonlySet<string> = new Set(['TimeoutError', 'AbortError']);
const TIMEOUT_CODES: ReadonlySet<string> = new Set([
  'active_policy_refresh_timeout',
  'public_aci_operation_deadline',
]);
const OUTPUT_EXHAUSTED = / exhausted its output tokens$/;
const UNCLASSIFIED: SpanFailure = Object.freeze({ outcome: 'error_code' });

/** A failed span's closed outcome and its message-failure slug; no error text survives. */
export function inferenceSpanFailure(error: unknown): SpanFailure {
  try {
    const errorCode = messageFailureCode('synthesis', error);
    const links = causeChain(error);
    if (links.some(isTimeout)) return { outcome: 'timeout', errorCode };
    if (links.some(isExhausted)) return { outcome: 'exhausted', errorCode };
    return { outcome: 'error_code', errorCode };
  } catch {
    return UNCLASSIFIED;
  }
}

function causeChain(error: unknown): Error[] {
  const links: Error[] = [];
  let current = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
    links.push(current);
    current = current.cause;
  }
  return links;
}

function isTimeout(link: Error): boolean {
  if (link instanceof DOMException) return TIMEOUT_ERROR_NAMES.has(link.name);
  return TIMEOUT_CODES.has(link.message);
}

// A rate limit or a reply cut off at its token budget: the provider ran out, the call did not break.
function isExhausted(link: Error): boolean {
  if (link instanceof ProviderHttpError) return link.status === HTTP_TOO_MANY_REQUESTS;
  return OUTPUT_EXHAUSTED.test(link.message);
}
