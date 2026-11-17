import type { OAUTH_REFRESH_OUTCOMES } from '@folklore/contracts/enclave';

export type FailedOAuthRefreshOutcome = Exclude<(typeof OAUTH_REFRESH_OUTCOMES)[number], 'success'>;

/** Names the refresh outcome that kept a 401 from recovering; the 401 stays as its cause. */
export class OAuthRefreshFailedError extends Error {
  constructor(
    readonly code: FailedOAuthRefreshOutcome,
    cause: unknown,
  ) {
    super('oauth_refresh_failed', { cause });
  }
}
