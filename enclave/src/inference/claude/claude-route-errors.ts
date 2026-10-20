import {
  ProviderRouteError,
  type ProviderDeferralClass,
  type ProviderRouteErrorInit,
} from '@folklore/inference';

export const CLAUDE_UPSTREAM_TIMEOUT = 'claude_upstream_timeout';
export const CLAUDE_OPERATION_DEADLINE = 'claude_operation_deadline';
export const CLAUDE_ROUTE_PROVIDER_MISMATCH = 'claude_route_provider_mismatch';

export const CLAUDE_TRANSIENT_STATUSES: ReadonlySet<number> = new Set([429, 502, 503, 504, 529]);

export const CLAUDE_DEFERRABLE_CODES: ReadonlySet<string> = new Set([
  'claude_spend_limit_reached',
  'claude_workspace_spend_limit',
  'claude_rate_limited',
  'claude_overloaded',
  CLAUDE_UPSTREAM_TIMEOUT,
  'claude_credential_unavailable',
  'claude_credential_rejected',
  'claude_organization_mismatch',
  'claude_workspace_mismatch',
]);

// A call that timed out may have spent tokens that never came back metered.
export const CLAUDE_SLOW_CODES: ReadonlySet<string> = new Set([
  CLAUDE_UPSTREAM_TIMEOUT,
  CLAUDE_OPERATION_DEADLINE,
]);

const ANTHROPIC_PROVIDER = 'anthropic';

/** A Claude route refusal: the message is the code, and no upstream text or cause is kept. */
export class ClaudeRouteError extends ProviderRouteError {
  constructor(code: string, status?: number, retryAfterMs?: number, fallbackEligible = false) {
    super(ClaudeRouteError.initFor(code, status, retryAfterMs, fallbackEligible));
    this.name = 'ClaudeRouteError';
  }

  private static initFor(
    code: string,
    status: number | undefined,
    retryAfterMs: number | undefined,
    fallbackEligible: boolean,
  ): ProviderRouteErrorInit {
    const deferral = ClaudeRouteError.deferralOf(code);
    return {
      provider: ANTHROPIC_PROVIDER,
      code,
      marksSlow: CLAUDE_SLOW_CODES.has(code),
      fallbackEligible,
      ...(status === undefined ? {} : { status }),
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
      ...(deferral === undefined ? {} : { deferral }),
    };
  }

  private static deferralOf(code: string): ProviderDeferralClass | undefined {
    if (code === CLAUDE_UPSTREAM_TIMEOUT) return 'slow';
    return CLAUDE_DEFERRABLE_CODES.has(code) ? 'outage' : undefined;
  }
}

export const CLAUDE_ROUTE_CONFIG_INVALID = 'claude_route_config_invalid';

export class ClaudeRouteConfigError extends Error {
  constructor(readonly rule: string) {
    super(`${CLAUDE_ROUTE_CONFIG_INVALID}:${rule}`);
    this.name = 'ClaudeRouteConfigError';
  }
}
