import { AsyncLocalStorage } from 'node:async_hooks';
import { ClaudeRouteError } from './claude-route-errors.js';

export const CLAUDE_UPSTREAM_TIMEOUT = 'claude_upstream_timeout';
export const CLAUDE_OPERATION_DEADLINE = 'claude_operation_deadline';
const MESSAGE_DEADLINE_CODE = 'synthesis_message_deadline_exceeded';

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

export interface ClaudeOutageRecord {
  readonly code: string;
  readonly upstream: string | undefined;
}

export type ClaudeDeferralReason = 'provider_outage' | 'provider_slow';

interface OutageStore {
  readonly records: ClaudeOutageRecord[];
}

class ClaudeOutageStore {
  private readonly storage = new AsyncLocalStorage<OutageStore>();

  run<T>(fn: () => Promise<T>): Promise<T> {
    return this.storage.run({ records: [] }, fn);
  }

  // Shadow arms record into a store of their own, so a shadow outage never defers production.
  isolated<T>(fn: () => Promise<T>): Promise<T> {
    return this.storage.run({ records: [] }, fn);
  }

  record(entry: ClaudeOutageRecord): void {
    this.storage.getStore()?.records.push(entry);
  }

  seen(): readonly ClaudeOutageRecord[] {
    return [...(this.storage.getStore()?.records ?? [])];
  }
}

export const claudeOutageScope = new ClaudeOutageStore();

export function claudeDeferral(
  error: unknown,
  seen: readonly ClaudeOutageRecord[],
  upstreamPaused: (upstream: string) => boolean,
): ClaudeDeferralReason | undefined {
  if (error instanceof ClaudeRouteError) return routeErrorDeferral(error, seen);
  if (isMessageDeadline(error) && seen.some((entry) => pausedUpstream(entry, upstreamPaused))) {
    return 'provider_slow';
  }
  return undefined;
}

function routeErrorDeferral(
  error: ClaudeRouteError,
  seen: readonly ClaudeOutageRecord[],
): ClaudeDeferralReason | undefined {
  if (error.code === CLAUDE_UPSTREAM_TIMEOUT) return 'provider_slow';
  if (!CLAUDE_DEFERRABLE_CODES.has(error.code)) return undefined;
  return seen.some((entry) => CLAUDE_SLOW_CODES.has(entry.code))
    ? 'provider_slow'
    : 'provider_outage';
}

function isMessageDeadline(error: unknown): boolean {
  return error instanceof Error && error.message === MESSAGE_DEADLINE_CODE;
}

function pausedUpstream(
  entry: ClaudeOutageRecord,
  upstreamPaused: (upstream: string) => boolean,
): boolean {
  return (
    CLAUDE_DEFERRABLE_CODES.has(entry.code) &&
    entry.upstream !== undefined &&
    upstreamPaused(entry.upstream)
  );
}
