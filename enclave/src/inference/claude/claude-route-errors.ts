import { ProviderHttpError } from '@folklore/inference';

const NOT_AN_HTTP_STATUS = 0;

export const CLAUDE_TRANSIENT_STATUSES: ReadonlySet<number> = new Set([429, 502, 503, 504, 529]);

/** A Claude route refusal: the message is the code, and no upstream text or cause is kept. */
export class ClaudeRouteError extends ProviderHttpError {
  readonly code: string;

  constructor(code: string, status: number = NOT_AN_HTTP_STATUS, retryAfterMs?: number) {
    super(code, status, retryAfterMs);
    this.name = 'ClaudeRouteError';
    this.code = code;
  }
}

export const CLAUDE_ROUTE_CONFIG_INVALID = 'claude_route_config_invalid';

export class ClaudeRouteConfigError extends Error {
  constructor(readonly rule: string) {
    super(`${CLAUDE_ROUTE_CONFIG_INVALID}:${rule}`);
    this.name = 'ClaudeRouteConfigError';
  }
}
