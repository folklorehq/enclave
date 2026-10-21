import { ProviderRouteError, type ProviderRouteErrorInit } from '@folklore/inference';

const OPENAI_PROVIDER = 'openai';

export const OPENAI_CREDENTIAL_CODES = [
  'openai_credential_missing',
  'openai_credential_access_denied',
  'openai_credential_identity_invalid',
  'openai_credential_version_invalid',
  'openai_credential_value_invalid',
  'openai_credential_decrypt_failed',
  'openai_credential_unavailable',
  'openai_credential_rejected',
] as const;

export const OPENAI_ROUTE_CODES = [
  'openai_embed_route_invalid',
  'embedding_provider_absent',
  'embedding_space_not_phala',
] as const;

export const OPENAI_BACKEND_CODES = [
  'openai_embed_input_empty',
  'openai_input_too_long',
  'openai_request_invalid',
  'openai_rate_limited',
  'openai_quota_exhausted',
  'openai_overloaded',
  'openai_response_invalid',
  'openai_model_mismatch',
  'openai_embedding_dimension_mismatch',
  'openai_embedding_non_finite',
] as const;

export const OPENAI_BINDING_CODES = [
  'openai_organization_mismatch',
  'openai_project_mismatch',
  'openai_project_hash_required',
] as const;

export const OPENAI_TRANSPORT_CODES = [
  'openai_request_refused',
  'openai_tls_untrusted',
  'openai_tls_root_set_mismatch',
] as const;

export const OPENAI_EMBED_CODES = [
  ...OPENAI_ROUTE_CODES,
  ...OPENAI_BACKEND_CODES,
  ...OPENAI_BINDING_CODES,
  ...OPENAI_TRANSPORT_CODES,
  ...OPENAI_CREDENTIAL_CODES,
] as const;

export type OpenAIEmbedCode = (typeof OPENAI_EMBED_CODES)[number];

export const OPENAI_TRANSIENT_STATUSES: ReadonlySet<number> = new Set([429, 500, 502, 503, 504]);

/** An embeddings refusal: the message is the code, and no upstream text or cause is kept. */
export class OpenAIEmbedRouteError extends ProviderRouteError {
  readonly permanent: boolean;

  constructor(code: OpenAIEmbedCode, status?: number, permanent = false, retryAfterMs?: number) {
    super(OpenAIEmbedRouteError.initFor(code, status, retryAfterMs));
    this.name = 'OpenAIEmbedRouteError';
    this.permanent = permanent;
  }

  private static initFor(
    code: OpenAIEmbedCode,
    status: number | undefined,
    retryAfterMs: number | undefined,
  ): ProviderRouteErrorInit {
    return {
      provider: OPENAI_PROVIDER,
      code,
      marksSlow: false,
      fallbackEligible: false,
      ...(status === undefined ? {} : { status }),
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    };
  }
}
