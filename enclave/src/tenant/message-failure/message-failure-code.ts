import {
  AciSessionVerificationError,
  AciTrustStateError,
  AciVerificationError,
  ActivePolicyCarrierVerificationError,
  ControlledGatewayModelArtifactVerificationError,
  ForwardLeaseStoreError,
  GenerationContextFloorError,
  ModelProvenanceGateError,
  OfficialAciExchangeError,
  OfficialAciReceiptVerificationError,
  PreForwardAdmissionError,
  PreForwardRouteProofVerificationError,
  ProviderNativeModelArtifactVerificationError,
  VerifiedActivePolicySnapshotVerifierError,
} from '@folklore/inference';
import { AppError } from '@folklore/errors';
import { ZodError } from 'zod';
import { ProviderEgressError, ProviderRejectedError } from '../../egress/provider-token-fetch.js';
import { EvidenceAnchorVerifierError } from '../../inference/EvidenceAnchorVerifier.js';
import { GatewayEvidenceRecorderError } from '../../inference/GatewayEvidenceRecorder.js';
import { TenantPolicyBoundInferenceError } from '../../inference/TenantPolicyBoundInference.js';
import { TrustedEvidenceContextError } from '../../inference/TrustedEvidenceContextProvider.js';
import { TrustedTimeAuthorityError } from '../../inference/TrustedTimeAuthority.js';
import { errorType } from '../../logging/error-fields.js';
import type { PullNotProcessedReason } from '../../pull/pull-runner.js';
import { TenantContextZeroizedError } from '../tenant-context.js';
import { CrossTenantRoutingError, TenantMessageRouteError } from '../tenant-message-router.js';
import { UnknownTenantError } from '../tenant-registry.js';
import { inferenceRoleOf } from './inference-role-tag.js';
import { MESSAGE_SENTENCE_REASONS } from './message-failure-sentences.js';
import { sentenceKey } from './sentence-key.js';
import { MESSAGE_FAILURE_REASONS, NETWORK_ERROR_CODES } from './message-failure-reasons.js';

const CLASS_PREFIX = 'class';
const PLAIN_ERROR_CLASS = 'Error';
const CLASS_NAME_SHAPE = /^[A-Z][A-Za-z0-9]{2,40}$/;
// Longer than any table sentence, so an oversized message is never hashed.
const MAX_SENTENCE_LENGTH = 512;
export const WRAPPED_CAUSE_PREFIXES = ['theme_embed', 'visibility_renewal'] as const;
export type WrappedCausePrefix = (typeof WRAPPED_CAUSE_PREFIXES)[number];
const WRAPPED_CAUSE_PREFIX_SET: ReadonlySet<string> = new Set(WRAPPED_CAUSE_PREFIXES);
// Module-private, so only `recordWrappedCause` can attach a reason to a wrapper.
const WRAPPED_CAUSE_REASONS = new WeakMap<Error, string>();

type Classification = { readonly reason: string } | { readonly className: string };

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
  'synthesis',
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
    /^OpenAI-compatible endpoint returned a malformed (?:embedding|chat|stream) response$/,
    () => 'provider_response_malformed',
  ],
  [/^OpenAI-compatible endpoint exhausted its output tokens$/, () => 'provider_output_exhausted'],
  [
    /^OpenAI-compatible endpoint returned [0-9]{1,6}-dim embedding, expected [0-9]{1,6}$/,
    () => 'provider_embedding_dimension_mismatch',
  ],
];

// Reasons a provider call raises; the inference role they failed under is prefixed when known.
const ROLE_TAGGED_REASON_PREFIXES = ['provider_', 'aci_'] as const;
const ROLE_TAGGED_REASONS: ReadonlySet<string> = new Set(['request_aborted', 'request_timeout']);

type ErrorClass = abstract new (...args: never[]) => Error;

const FIXED_CLASS_REASONS: ReadonlyArray<readonly [ErrorClass, string]> = [
  [ProviderRejectedError, 'provider_rejected'],
  [ProviderEgressError, 'provider_egress_denied'],
  [CrossTenantRoutingError, 'cross_tenant'],
  [UnknownTenantError, 'tenant_unassigned'],
  [TenantContextZeroizedError, 'tenant_zeroized'],
  [PreForwardAdmissionError, 'aci_admission_refused'],
  // A schema refusal names no field: an issue path or message can echo the parsed value.
  [ZodError, 'schema_invalid'],
];

// Each of these carries a code typed as a closed union; the prefix keeps the class distinguishable.
const TYPED_CODE_PREFIXES: ReadonlyArray<readonly [ErrorClass, string]> = [
  [AciVerificationError, 'aci'],
  [AciSessionVerificationError, 'aci_session'],
  [OfficialAciReceiptVerificationError, 'aci_receipt'],
  [OfficialAciExchangeError, 'aci_exchange'],
  [AciTrustStateError, 'aci_trust'],
  [ActivePolicyCarrierVerificationError, 'policy_carrier'],
  [GenerationContextFloorError, 'generation_floor'],
  [VerifiedActivePolicySnapshotVerifierError, 'policy_snapshot'],
  [ForwardLeaseStoreError, 'forward_lease'],
  [ModelProvenanceGateError, 'provenance_gate'],
  [ProviderNativeModelArtifactVerificationError, 'native_artifact'],
  [ControlledGatewayModelArtifactVerificationError, 'gateway_artifact'],
  [PreForwardRouteProofVerificationError, 'route_proof'],
  [EvidenceAnchorVerifierError, 'anchor'],
  [GatewayEvidenceRecorderError, 'gateway_evidence'],
  [TrustedEvidenceContextError, 'context'],
];

/** A fixed `<phase>_<reason>` slug for a failed message attempt; no message text, URL or id enters it. */
export function messageFailureCode(
  phase: MessageFailurePhase,
  error: unknown,
  step?: string,
): string {
  const classification = safeClassification(error);
  // A built-in class says nothing about where it was thrown, so the step is kept beside it.
  if ('reason' in classification) {
    const scoped = step !== undefined && BUILT_IN_ERROR_TYPES.has(classification.reason);
    return joinCode(scoped ? `${phase}_${step}` : phase, classification.reason);
  }
  return classCode(step === undefined ? phase : `${phase}_${step}`, classification.className);
}

/** Keeps only the classified reason of `cause` against `wrapper`, never the cause itself. */
export function recordWrappedCause(
  wrapper: Error,
  prefix: WrappedCausePrefix,
  cause: unknown,
): void {
  if (!WRAPPED_CAUSE_PREFIX_SET.has(prefix)) return;
  const classification = safeClassification(cause, `${prefix}_`.length);
  const reason =
    'reason' in classification
      ? classification.reason
      : `${CLASS_PREFIX}_${classification.className}`;
  if (reason === UNCLASSIFIED) return;
  const combined = `${prefix}_${reason}`;
  if (combined.length <= MAX_REASON_LENGTH && CODE_PATTERN.test(combined)) {
    WRAPPED_CAUSE_REASONS.set(wrapper, combined);
  }
}

// A thrown error can carry hostile getters or be a Proxy; naming it must never throw instead.
function safeClassification(error: unknown, reservedLength = 0): Classification {
  try {
    return classification(error, reservedLength);
  } catch {
    return { reason: UNCLASSIFIED };
  }
}

// The class part is truncated, never the phase or step ahead of it.
function classCode(head: string, className: string): string {
  const prefix = `${head}_${CLASS_PREFIX}`;
  const room = MAX_CODE_LENGTH - prefix.length - 1;
  const name = className.slice(0, Math.max(room, 0)).replace(/_+$/, '');
  return name === '' ? joinCode(head, UNCLASSIFIED) : joinCode(prefix, name);
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
// `reservedLength` is room a wrapper's prefix takes ahead of the reason.
function classification(error: unknown, reservedLength: number): Classification {
  const chain = causeChain(error);
  let reason: string | undefined;
  for (const link of chain) reason = linkReason(link) ?? reason;
  if (reason !== undefined) return { reason: roleTaggedReason(chain, reason, reservedLength) };
  reason = builtInClassReason(chain[chain.length - 1]);
  if (reason !== undefined) return { reason };
  const className = innermostClassName(chain);
  return className === undefined ? { reason: UNCLASSIFIED } : { className };
}

function roleTaggedReason(
  chain: readonly unknown[],
  reason: string,
  reservedLength: number,
): string {
  if (!isRoleTaggable(reason)) return reason;
  const role = chainRole(chain);
  if (role === undefined) return reason;
  const tagged = `${role}_${reason}`;
  return reservedLength + tagged.length <= MAX_REASON_LENGTH && CODE_PATTERN.test(tagged)
    ? tagged
    : reason;
}

function isRoleTaggable(reason: string): boolean {
  return (
    ROLE_TAGGED_REASONS.has(reason) ||
    ROLE_TAGGED_REASON_PREFIXES.some((prefix) => reason.startsWith(prefix))
  );
}

function chainRole(chain: readonly unknown[]): string | undefined {
  for (const link of [...chain].reverse()) {
    const role = inferenceRoleOf(link);
    if (role !== undefined) return role;
  }
  return undefined;
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
  const wrapped = WRAPPED_CAUSE_REASONS.get(link);
  if (wrapped !== undefined) return wrapped;
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
    messageReason(link.message) ??
    fixedSentenceReason(link.message) ??
    networkCodeReason(link) ??
    abortReason(link) ??
    awsHttpReason(link)
  );
}

// Exact equality only: a registered slug, or the hash of a code-authored sentence in the table.
function messageReason(message: unknown): string | undefined {
  if (typeof message !== 'string') return undefined;
  return (
    known(message) ??
    (message.length <= MAX_SENTENCE_LENGTH
      ? MESSAGE_SENTENCE_REASONS.get(sentenceKey(message))
      : undefined)
  );
}

function fixedSentenceReason(message: string): string | undefined {
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

function builtInClassReason(error: unknown): string | undefined {
  const type = errorType(error);
  return type !== BASE_ERROR_TYPE && BUILT_IN_ERROR_TYPES.has(type) ? type : undefined;
}

// A constructor name is a code identifier, never content; the innermost named class wins.
function innermostClassName(chain: readonly unknown[]): string | undefined {
  for (const link of [...chain].reverse()) {
    if (!(link instanceof Error)) continue;
    const name = (Object.getPrototypeOf(link) as { constructor?: { name?: unknown } } | null)
      ?.constructor?.name;
    if (typeof name === 'string' && name !== PLAIN_ERROR_CLASS && CLASS_NAME_SHAPE.test(name)) {
      return snakeCase(name);
    }
  }
  return undefined;
}

function snakeCase(identifier: string): string {
  return identifier
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}
