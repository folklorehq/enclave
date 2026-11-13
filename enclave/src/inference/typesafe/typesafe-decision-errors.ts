import { ProviderRouteError, type ProviderRouteErrorInit } from '@folklore/inference';

const TYPESAFE_PROVIDER = 'typesafe';

export const TYPESAFE_DECISION_CODES = [
  'typesafe_decision_route_invalid',
  'typesafe_org_out_of_scope',
  'typesafe_question_unregistered',
  'typesafe_state_key_invalid',
  'typesafe_request_too_large',
  'typesafe_request_invalid',
  'typesafe_rate_limited',
  'typesafe_overloaded',
  'typesafe_unavailable',
  'typesafe_timeout',
  'typesafe_response_invalid',
  'typesafe_model_mismatch',
  'typesafe_request_refused',
  'typesafe_tls_untrusted',
  'typesafe_tls_root_set_mismatch',
  'typesafe_credential_missing',
  'typesafe_credential_access_denied',
  'typesafe_credential_identity_invalid',
  'typesafe_credential_version_invalid',
  'typesafe_credential_value_invalid',
  'typesafe_credential_decrypt_failed',
  'typesafe_credential_unavailable',
  'typesafe_credential_rejected',
  'typesafe_credential_binding_mismatch',
] as const;

export type TypeSafeDecisionCode = (typeof TYPESAFE_DECISION_CODES)[number];

/** A decision refusal: the message is the code; no upstream text or cause is kept. */
export class TypeSafeDecisionError extends ProviderRouteError {
  readonly permanent: boolean;

  constructor(
    code: TypeSafeDecisionCode,
    status?: number,
    permanent = false,
    retryAfterMs?: number,
  ) {
    super(TypeSafeDecisionError.initFor(code, status, retryAfterMs));
    this.name = 'TypeSafeDecisionError';
    this.permanent = permanent;
  }

  private static initFor(
    code: TypeSafeDecisionCode,
    status: number | undefined,
    retryAfterMs: number | undefined,
  ): ProviderRouteErrorInit {
    return {
      provider: TYPESAFE_PROVIDER,
      code,
      marksSlow: false,
      fallbackEligible: false,
      ...(status === undefined ? {} : { status }),
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    };
  }
}
