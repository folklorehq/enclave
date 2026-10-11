import { isFailureCodeSlug } from '@folklore/core';
import { guardFailureCode } from '../boot/guard-failure-code.js';
import { ProviderEgressError, ProviderRejectedError } from '../egress/provider-token-fetch.js';
import { OAuthRefusal } from './OAuthRefusal.js';

export const UNCLASSIFIED_REDEMPTION_REASON = 'oauth_redemption_unclassified';
const PROVIDER_EGRESS_REASON = 'provider_egress_failed';
const PROVIDER_REJECTED_REASON = 'provider_rejected';
const PROVIDER_OAUTH_ERROR_REASON = 'provider_oauth_error';
const PROVIDER_OAUTH_ERROR_CODE_PATTERN = /^[a-z_]{1,40}$/;
const MIN_HTTP_STATUS = 100;
const MAX_HTTP_STATUS = 599;

/** The failure's content-free reason, or `fallback` qualified by its error class when it has none. */
export function oauthFailureReason(error: unknown, fallback: string): string {
  if (error instanceof OAuthRefusal) {
    return isFailureCodeSlug(error.reason) ? error.reason : fallback;
  }
  if (error instanceof ProviderRejectedError) return providerRejectedReason(error.status);
  if (error instanceof ProviderEgressError) return PROVIDER_EGRESS_REASON;
  return guardFailureCode(error, fallback);
}

export function redemptionRefusalReason(error: unknown): string {
  return oauthFailureReason(error, UNCLASSIFIED_REDEMPTION_REASON);
}

/** Refuses under `code`, keeping the underlying failure's reason when it has one. */
export function refusalFrom(code: string, underlying: unknown): OAuthRefusal {
  return new OAuthRefusal(code, oauthFailureReason(underlying, code));
}

// A token endpoint may answer a bad exchange with HTTP 200 and an `error` field from its fixed set.
export function providerOAuthErrorReason(code: unknown): string {
  if (typeof code !== 'string' || !PROVIDER_OAUTH_ERROR_CODE_PATTERN.test(code)) {
    return PROVIDER_OAUTH_ERROR_REASON;
  }
  const reason = `${PROVIDER_OAUTH_ERROR_REASON}_${code}`;
  return isFailureCodeSlug(reason) ? reason : PROVIDER_OAUTH_ERROR_REASON;
}

function providerRejectedReason(status: number): string {
  return Number.isInteger(status) && status >= MIN_HTTP_STATUS && status <= MAX_HTTP_STATUS
    ? `${PROVIDER_REJECTED_REASON}_${status}`
    : PROVIDER_REJECTED_REASON;
}
