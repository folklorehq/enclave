import type { NormalizedFact, PullStats } from '@folklore/connectors';
import { PULL_CHARS_BUCKET, type PullStatsSignal } from '@folklore/contracts/enclave';
import { embedTextOf } from '../pipeline/index.js';
import type { ProcessedFact } from '../pipeline/index.js';

export type PullRunStats = PullStatsSignal;

export interface PullRunStatsInput {
  pulled: readonly NormalizedFact[];
  processed: readonly ProcessedFact[];
  connectorStats: PullStats | undefined;
  durationMs: number;
  hasMore: boolean;
  backfill: boolean;
}

/** Counts and bucketed totals only: no id, title or text may enter this shape. */
export function buildPullRunStats(input: PullRunStatsInput): PullRunStats {
  const base: PullStats = input.connectorStats ?? {
    listed: input.pulled.length,
    emitted: input.pulled.length,
    apiCalls: 0,
    listingRestarts: 0,
    skipped: {},
  };
  return {
    listed: base.listed,
    emitted: base.emitted,
    apiCalls: base.apiCalls,
    listingRestarts: base.listingRestarts,
    skipped: base.skipped,
    ...(base.bodyCharsBucket === undefined ? {} : { bodyCharsBucket: base.bodyCharsBucket }),
    ...(base.truncatedBodies === undefined ? {} : { truncatedBodies: base.truncatedBodies }),
    facts: input.processed.length,
    contentFacts: input.processed.filter((fact) => fact.kind === 'content').length,
    embedInputCharsBucket: embedInputCharsBucket(input.pulled),
    durationMs: Math.max(0, Math.round(input.durationMs)),
    hasMore: input.hasMore,
    backfill: input.backfill || input.connectorStats?.backfillChunk === true,
  };
}

function embedInputCharsBucket(pulled: readonly NormalizedFact[]): number {
  const chars = pulled
    .filter((fact) => fact.kind !== 'transition')
    .reduce((total, fact) => total + embedTextOf(fact).length, 0);
  return Math.ceil(chars / PULL_CHARS_BUCKET) * PULL_CHARS_BUCKET;
}
