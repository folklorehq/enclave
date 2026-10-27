import { randomUUID } from 'node:crypto';
import { z } from 'zod';

const TOMBSTONE_VERSION = 1;
const REPOSITORY_RETIREMENT_KEY = /^[^:]+:[^:]+:.+$/;
const ERASE_PASS_KEY = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[12]$/;

export const MAX_COMPLETED_ERASES = 64;

export const ALL_GENERATIONS = 'all';

export const codeGraphTombstoneSchema = z
  .object({
    version: z.literal(TOMBSTONE_VERSION),
    tombstoneId: z.string().uuid(),
    allRetiredEpoch: z.number().int().nonnegative(),
    retiredGenerations: z.array(z.string().uuid()),
    retiredRepositories: z.record(
      z.string().regex(REPOSITORY_RETIREMENT_KEY),
      z.number().int().nonnegative(),
    ),
    erasesInProgress: z.record(z.string().regex(ERASE_PASS_KEY), z.string()).default({}),
    completedErases: z
      .array(z.string().regex(ERASE_PASS_KEY))
      .max(MAX_COMPLETED_ERASES)
      .default([]),
  })
  .strict();

export type CodeGraphTombstone = z.infer<typeof codeGraphTombstoneSchema>;

export function newTombstone(): CodeGraphTombstone {
  return {
    version: TOMBSTONE_VERSION,
    tombstoneId: randomUUID(),
    allRetiredEpoch: 0,
    retiredGenerations: [],
    retiredRepositories: {},
    erasesInProgress: {},
    completedErases: [],
  };
}

export function withRetirement(
  tombstone: CodeGraphTombstone,
  retiredGeneration: string,
): CodeGraphTombstone {
  if (retiredGeneration === ALL_GENERATIONS) {
    return { ...tombstone, allRetiredEpoch: tombstone.allRetiredEpoch + 1 };
  }
  if (tombstone.retiredGenerations.includes(retiredGeneration)) return tombstone;
  return {
    ...tombstone,
    retiredGenerations: [...tombstone.retiredGenerations, retiredGeneration],
  };
}

export function repositoryRetirementKey(
  deploymentId: string,
  generation: string,
  repoNodeId: string,
): string {
  return `${deploymentId}:${generation}:${repoNodeId}`;
}

export function erasePassKey(eraseId: string, pass: 1 | 2): string {
  return `${eraseId}:${pass}`;
}

export function withEraseProgress(
  tombstone: CodeGraphTombstone,
  passKey: string,
  cursor: string,
): CodeGraphTombstone {
  if (tombstone.completedErases.includes(passKey)) return tombstone;
  const stored = tombstone.erasesInProgress[passKey];
  if (stored !== undefined && stored >= cursor) return tombstone;
  return { ...tombstone, erasesInProgress: { ...tombstone.erasesInProgress, [passKey]: cursor } };
}

export function withFinishedErase(
  tombstone: CodeGraphTombstone,
  passKey: string,
): CodeGraphTombstone {
  if (tombstone.completedErases.includes(passKey)) return tombstone;
  const { [passKey]: _finished, ...rest } = tombstone.erasesInProgress;
  return {
    ...tombstone,
    erasesInProgress: rest,
    completedErases: [...tombstone.completedErases, passKey].slice(-MAX_COMPLETED_ERASES),
  };
}
