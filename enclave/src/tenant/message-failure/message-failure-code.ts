import {
  AciSessionVerificationError,
  AciVerificationError,
  OfficialAciExchangeError,
  OfficialAciReceiptVerificationError,
} from '@folklore/inference';
import { AppError } from '@folklore/errors';
import { ZodError } from 'zod';
import { ProviderEgressError, ProviderRejectedError } from '../../egress/provider-token-fetch.js';
import { TenantPolicyBoundInferenceError } from '../../inference/TenantPolicyBoundInference.js';
import { TrustedTimeAuthorityError } from '../../inference/TrustedTimeAuthority.js';
import { errorType } from '../../logging/error-fields.js';
import type { PullNotProcessedReason } from '../../pull/pull-runner.js';
import { TenantContextZeroizedError } from '../tenant-context.js';
import { CrossTenantRoutingError, TenantMessageRouteError } from '../tenant-message-router.js';
import { UnknownTenantError } from '../tenant-registry.js';
import {
  MESSAGE_FAILURE_REASONS,
  NETWORK_ERROR_CODES,
  PUBLIC_ACI_SESSION_MESSAGES,
} from './message-failure-reasons.js';

export const MESSAGE_FAILURE_PHASES = [
  'parse',
  'route',
  'decrypt',
  'pipeline',
  'encrypt',
  'store',
  'embed',
  'index',
  'archive',
  'emit',
  'release',
  'persist',
  'post_persist',
  'ack',
] as const;

export type MessageFailurePhase = (typeof MESSAGE_FAILURE_PHASES)[number];

const NOT_PROCESSED = 'not_processed';
const UNCLASSIFIED = 'unclassified';
const BASE_ERROR_TYPE = 'error';
const MAX_CAUSE_DEPTH = 8;
const MAX_CODE_LENGTH = 64;
const CODE_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const MAX_REASON_LENGTH =
  MAX_CODE_LENGTH - 1 - Math.max(...MESSAGE_FAILURE_PHASES.map((phase) => phase.length));
const BUILT_IN_ERROR_TYPES = new Set([
  'aggregate_error',
  'eval_error',
  'range_error',
  'reference_error',
  'syntax_error',
  'type_error',
  'uri_error',
]);

const NETWORK_PREFIX = 'network';
const AWS_HTTP_PREFIX = 'aws_http';
const AWS_FAULTS: ReadonlySet<unknown> = new Set(['client', 'server']);
const MIN_HTTP_STATUS = 100;
const MAX_HTTP_STATUS = 599;
const PUBLIC_ACI_SESSION_SENTENCE_PREFIX = 'public ACI ';
const PUBLIC_ACI_SESSION_PREFIX = 'public_aci';
const ABORT_REASONS: ReadonlyMap<string, string> = new Map([
  ['AbortError', 'request_aborted'],
  ['TimeoutError', 'request_timeout'],
]);
// The provider backend's own sentences under its default label; the status is a bare HTTP code.
const PROVIDER_MESSAGE_REASONS: ReadonlyArray<readonly [RegExp, (status: string) => string]> = [
  [
    /^OpenAI-compatible endpoint (?:embed|generate|tool call|stream) failed: ([1-5][0-9]{2})$/,
    (status) => `provider_http_${status}`,
  ],
  [
    /^OpenAI-compatible endpoint returned no (?:embedding|content)$/,
    () => 'provider_response_empty',
  ],
  [
    /^OpenAI-compatible endpoint returned [0-9]{1,6}-dim embedding, expected [0-9]{1,6}$/,
    () => 'provider_embedding_dimension_mismatch',
  ],
];

type ErrorClass = abstract new (...args: never[]) => Error;

const FIXED_CLASS_REASONS: ReadonlyArray<readonly [ErrorClass, string]> = [
  [ProviderRejectedError, 'provider_rejected'],
  [ProviderEgressError, 'provider_egress_denied'],
  [CrossTenantRoutingError, 'cross_tenant'],
  [UnknownTenantError, 'tenant_unassigned'],
  [TenantContextZeroizedError, 'tenant_zeroized'],
  // A schema refusal names no field: an issue path or message can echo the parsed value.
  [ZodError, 'schema_invalid'],
];

// Each of these carries a code typed as a closed union; the prefix keeps the class distinguishable.
const TYPED_CODE_PREFIXES: ReadonlyArray<readonly [ErrorClass, string]> = [
  [AciVerificationError, 'aci'],
  [AciSessionVerificationError, 'aci_session'],
  [OfficialAciReceiptVerificationError, 'aci_receipt'],
  [OfficialAciExchangeError, 'aci_exchange'],
];

/** A fixed `<phase>_<reason>` slug for a failed message attempt; no message text, URL or id enters it. */
export function messageFailureCode(phase: MessageFailurePhase, error: unknown): string {
  return joinCode(phase, safeFailureReason(error));
}

// A thrown error can carry hostile getters or be a Proxy; naming it must never throw instead.
function safeFailureReason(error: unknown): string {
  try {
    return failureReason(error);
  } catch {
    return UNCLASSIFIED;
  }
}

/** The slug for a delivery the router declined to process, from its closed reason set only. */
export function notProcessedFailureCode(reason: PullNotProcessedReason | undefined): string {
  return joinCode(
    NOT_PROCESSED,
    reason !== undefined && MESSAGE_FAILURE_REASONS.has(reason) ? reason : UNCLASSIFIED,
  );
}

function joinCode(prefix: string, reason: string): string {
  const code = `${prefix}_${reason}`;
  return code.length <= MAX_CODE_LENGTH && CODE_PATTERN.test(code)
    ? code
    : `${prefix}_${UNCLASSIFIED}`;
}

// The innermost recognised link names the root cause; wrappers add only their phase.
function failureReason(error: unknown): string {
  const chain = causeChain(error);
  let reason: string | undefined;
  for (const link of chain) reason = linkReason(link) ?? reason;
  return reason ?? builtInClassReason(chain[chain.length - 1]);
}

function causeChain(error: unknown): unknown[] {
  const chain: unknown[] = [error];
  let current = error;
  while (chain.length < MAX_CAUSE_DEPTH) {
    const cause = ownCause(current);
    if (cause === undefined || chain.includes(cause)) break;
    chain.push(cause);
    current = cause;
  }
  return chain;
}

function ownCause(value: unknown): unknown {
  if (!(value instanceof Error)) return undefined;
  try {
    return Object.getOwnPropertyDescriptor(value, 'cause')?.value as unknown;
  } catch {
    return undefined;
  }
}

function linkReason(link: unknown): string | undefined {
  if (!(link instanceof Error)) return undefined;
  if (link instanceof TenantPolicyBoundInferenceError) {
    return known(link.reason) ?? known(link.code);
  }
  if (link instanceof TrustedTimeAuthorityError) return known(link.code);
  if (link instanceof TenantMessageRouteError) return known(link.errorType);
  for (const [errorClass, reason] of FIXED_CLASS_REASONS) {
    if (link instanceof errorClass) return reason;
  }
  for (const [errorClass, prefix] of TYPED_CODE_PREFIXES) {
    if (link instanceof errorClass) return typedCodeReason(prefix, link);
  }
  if (link instanceof AppError) return known(link.code);
  return (
    known(link.message) ??
    fixedSentenceReason(link.message) ??
    networkCodeReason(link) ??
    abortReason(link) ??
    awsHttpReason(link)
  );
}

function fixedSentenceReason(message: string): string | undefined {
  if (PUBLIC_ACI_SESSION_MESSAGES.has(message)) {
    const words = message.slice(PUBLIC_ACI_SESSION_SENTENCE_PREFIX.length).split(' ');
    return [PUBLIC_ACI_SESSION_PREFIX, ...words].join('_');
  }
  for (const [pattern, reason] of PROVIDER_MESSAGE_REASONS) {
    const match = pattern.exec(message);
    if (match) return reason(match[1] ?? '');
  }
  return undefined;
}

function networkCodeReason(error: Error): string | undefined {
  const code = (error as Error & { code?: unknown }).code;
  return typeof code === 'string' && NETWORK_ERROR_CODES.has(code)
    ? `${NETWORK_PREFIX}_${code.toLowerCase()}`
    : undefined;
}

function abortReason(error: Error): string | undefined {
  return error instanceof DOMException ? ABORT_REASONS.get(error.name) : undefined;
}

// An AWS SDK service exception carries its HTTP status in `$metadata`; only the bare status is named.
function awsHttpReason(error: Error): string | undefined {
  const { $fault: fault, $metadata: metadata } = error as Error & {
    $fault?: unknown;
    $metadata?: { httpStatusCode?: unknown };
  };
  const status = metadata?.httpStatusCode;
  return AWS_FAULTS.has(fault) &&
    typeof status === 'number' &&
    Number.isInteger(status) &&
    status >= MIN_HTTP_STATUS &&
    status <= MAX_HTTP_STATUS
    ? `${AWS_HTTP_PREFIX}_${status}`
    : undefined;
}

function typedCodeReason(prefix: string, error: Error): string {
  const code = (error as Error & { code?: unknown }).code;
  const reason = `${prefix}_${typeof code === 'string' ? code : UNCLASSIFIED}`;
  return reason.length <= MAX_REASON_LENGTH && CODE_PATTERN.test(reason) ? reason : prefix;
}

function known(value: unknown): string | undefined {
  return typeof value === 'string' && MESSAGE_FAILURE_REASONS.has(value) ? value : undefined;
}

function builtInClassReason(error: unknown): string {
  const type = errorType(error);
  return type !== BASE_ERROR_TYPE && BUILT_IN_ERROR_TYPES.has(type) ? type : UNCLASSIFIED;
}
