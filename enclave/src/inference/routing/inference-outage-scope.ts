import { AsyncLocalStorage } from 'node:async_hooks';
import type { InferenceDeferralReason } from '@folklore/contracts';
import { ProviderRouteError } from '@folklore/inference';

const MESSAGE_DEADLINE_CODE = 'synthesis_message_deadline_exceeded';

export interface InferenceOutageRecord {
  readonly code: string;
  readonly upstream: string | undefined;
  readonly deferrable: boolean;
  readonly marksSlow: boolean;
}

interface MessageFlags {
  fallbackAlarmed: boolean;
}

interface OutageStore {
  readonly records: InferenceOutageRecord[];
  readonly flags: MessageFlags;
  readonly attempt?: InferenceOutageRecord[];
}

class InferenceOutageStore {
  private readonly storage = new AsyncLocalStorage<OutageStore>();

  run<T>(fn: () => Promise<T>): Promise<T> {
    return this.storage.run({ records: [], flags: { fallbackAlarmed: false } }, fn);
  }

  // Shadow arms record into a store of their own, so a shadow outage never defers production.
  isolated<T>(fn: () => Promise<T>): Promise<T> {
    return this.run(fn);
  }

  record(entry: InferenceOutageRecord): void {
    const store = this.storage.getStore();
    if (store === undefined) return;
    store.records.push(entry);
    store.attempt?.push(entry);
  }

  // The outages recorded inside `fn`'s own async chain, apart from any concurrent call's.
  attempt<T>(fn: () => Promise<T>): {
    readonly result: Promise<T>;
    readonly made: () => InferenceOutageRecord[];
  } {
    const parent = this.storage.getStore();
    if (parent === undefined) return { result: fn(), made: () => [] };
    const made: InferenceOutageRecord[] = [];
    const result = this.storage.run({ ...parent, attempt: made }, fn);
    return { result, made: () => [...made] };
  }

  // A failure that a fallback then answered must not class a later, unrelated error as a deferral.
  discard(entries: readonly InferenceOutageRecord[]): void {
    const store = this.storage.getStore();
    if (store === undefined) return;
    for (const entry of entries) {
      const index = store.records.indexOf(entry);
      if (index >= 0) store.records.splice(index, 1);
    }
  }

  firstFallbackInMessage(): boolean {
    const store = this.storage.getStore();
    if (store === undefined) return true;
    const first = !store.flags.fallbackAlarmed;
    store.flags.fallbackAlarmed = true;
    return first;
  }

  seen(): readonly InferenceOutageRecord[] {
    return [...(this.storage.getStore()?.records ?? [])];
  }
}

export const inferenceOutageScope = new InferenceOutageStore();

export function inferenceDeferral(
  error: unknown,
  seen: readonly InferenceOutageRecord[],
  upstreamPaused: (upstream: string) => boolean,
): InferenceDeferralReason | undefined {
  if (error instanceof ProviderRouteError) return routeErrorDeferral(error, seen);
  if (isMessageDeadline(error) && seen.some((entry) => pausedUpstream(entry, upstreamPaused))) {
    return 'provider_slow';
  }
  return undefined;
}

function routeErrorDeferral(
  error: ProviderRouteError,
  seen: readonly InferenceOutageRecord[],
): InferenceDeferralReason | undefined {
  if (error.deferral === 'slow') return 'provider_slow';
  if (error.deferral === undefined) return undefined;
  return seen.some((entry) => entry.marksSlow) ? 'provider_slow' : 'provider_outage';
}

function isMessageDeadline(error: unknown): boolean {
  return error instanceof Error && error.message === MESSAGE_DEADLINE_CODE;
}

function pausedUpstream(
  entry: InferenceOutageRecord,
  upstreamPaused: (upstream: string) => boolean,
): boolean {
  return entry.deferrable && entry.upstream !== undefined && upstreamPaused(entry.upstream);
}
