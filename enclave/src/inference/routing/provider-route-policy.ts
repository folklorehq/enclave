import type { RoutedProviderId } from '@folklore/contracts';
import { CLAUDE_REQUEST_TOO_LARGE } from '../claude/claude-request.js';
import { CLAUDE_TRANSIENT_STATUSES } from '../claude/claude-route-errors.js';

export interface ProviderRoutePolicy {
  readonly transientStatuses: ReadonlySet<number>;
  readonly upstreamKeyPrefix: string;
  readonly cacheRouteLabel: string;
}

const ANTHROPIC_POLICY: ProviderRoutePolicy = Object.freeze({
  transientStatuses: CLAUDE_TRANSIENT_STATUSES,
  upstreamKeyPrefix: 'anthropic/',
  // The label predates the provider registry and is part of every cached Claude operation key.
  cacheRouteLabel: 'claude',
});

export const PROVIDER_ROUTE_POLICY: Readonly<Record<RoutedProviderId, ProviderRoutePolicy>> =
  Object.freeze({ anthropic: ANTHROPIC_POLICY });

export const REQUEST_TOO_LARGE_CODES: ReadonlySet<string> = new Set([CLAUDE_REQUEST_TOO_LARGE]);
