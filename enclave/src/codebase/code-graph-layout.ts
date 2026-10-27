const ROOT = 'code-graph';
const NAMES_SEGMENT = 'names/v1';
const QUARANTINE_SEGMENT = 'quarantine/v1';
const UNPARSED_SEGMENT = 'unparsed';
const SHARD_KEY_SEGMENTS = 3;

export const QUARANTINE_GENERATION = 'quarantine';

export interface ParsedShardKey {
  generation: string;
  repoNodeId: string;
  shard: string;
}

export function codeGraphTombstoneKey(orgId: string): string {
  return `${ROOT}/${orgId}/tombstone/v1.json`;
}

export function codeGraphNamesPrefix(orgId: string, generation?: string): string {
  const base = `${ROOT}/${orgId}/${NAMES_SEGMENT}/`;
  return generation === undefined ? base : `${base}${generation}/`;
}

export function codeGraphQuarantinePrefix(orgId: string): string {
  return `${ROOT}/${orgId}/${QUARANTINE_SEGMENT}/`;
}

export function codeGraphShardKey(
  orgId: string,
  generation: string,
  repoNodeId: string,
  shard: string,
): string {
  return `${codeGraphNamesPrefix(orgId, generation)}${repoNodeId}/${shard}`;
}

export function parseShardKey(orgId: string, key: string): ParsedShardKey {
  const [generation, repoNodeId, shard] = segmentsAfter(codeGraphNamesPrefix(orgId), key);
  return {
    generation: generation ?? UNPARSED_SEGMENT,
    repoNodeId: repoNodeId ?? UNPARSED_SEGMENT,
    shard: shard ?? UNPARSED_SEGMENT,
  };
}

export function parseQuarantineKey(orgId: string, key: string): ParsedShardKey {
  const [repoNodeId, shard] = segmentsAfter(codeGraphQuarantinePrefix(orgId), key);
  return {
    generation: QUARANTINE_GENERATION,
    repoNodeId: repoNodeId ?? UNPARSED_SEGMENT,
    shard: shard ?? UNPARSED_SEGMENT,
  };
}

function segmentsAfter(prefix: string, key: string): string[] {
  return key.slice(prefix.length).split('/', SHARD_KEY_SEGMENTS);
}
