import type { RoutingMode } from './routing-allowlist.js';
import { SIGNATURE_VERIFIER_SOURCES } from './signature-verifier.js';

const REJECTION_STATUS = {
  source_unrecognized: 400,
  tenant_invalid: 401,
  auth_unsupported: 401,
  auth_malformed: 401,
  signature_invalid: 401,
  tenant_unresolved: 401,
  routing_denied: 401,
  payload_too_large: 413,
  rate_limited: 429,
  secret_unavailable: 503,
  routing_unavailable: 503,
  verification_capture_unavailable: 503,
  dispatcher_auth_unavailable: 503,
  downstream_failed: 503,
} as const;

export type WebhookRejectionReason = keyof typeof REJECTION_STATUS;

const REJECTED_EVENT = 'dispatcher_webhook_rejected';
const ACCEPTED_EVENT = 'dispatcher_webhook_accepted';
const UNRECOGNIZED_SOURCE = 'unrecognized';
const KNOWN_SOURCES: ReadonlySet<string> = new Set(SIGNATURE_VERIFIER_SOURCES);

// The path segment is caller-chosen, so only a name from the closed verifier set is ever logged.
export function loggableSource(source: string | undefined): string {
  return source !== undefined && KNOWN_SOURCES.has(source) ? source : UNRECOGNIZED_SOURCE;
}

export function rejectWebhook(
  source: string | undefined,
  mode: RoutingMode,
  reason: WebhookRejectionReason,
): { statusCode: number } {
  console.warn(
    JSON.stringify({ msg: REJECTED_EVENT, source: loggableSource(source), mode, reason }),
  );
  return { statusCode: REJECTION_STATUS[reason] };
}

export function acceptWebhook(source: string, mode: RoutingMode): { statusCode: 200 } {
  console.log(JSON.stringify({ msg: ACCEPTED_EVENT, source: loggableSource(source), mode }));
  return { statusCode: 200 };
}
