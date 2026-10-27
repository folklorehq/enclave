import type { CodebaseGraphEraseResponse } from '@folklore/contracts/enclave';
import {
  CODE_GRAPH_ERASE_UNAVAILABLE,
  CODE_GRAPH_TOMBSTONE_UNAVAILABLE,
  CodeGraphStoreUnavailableError,
} from './code-graph-failure.js';
import {
  codeGraphNamesPrefix,
  codeGraphQuarantinePrefix,
  parseQuarantineKey,
  parseShardKey,
  type ParsedShardKey,
} from './code-graph-layout.js';
import {
  ALL_GENERATIONS,
  erasePassKey,
  newTombstone,
  withEraseProgress,
  withFinishedErase,
  withRetirement,
  type CodeGraphTombstone,
} from './code-graph-tombstone.js';
import {
  UNRECORDED_TOMBSTONE_MARKER,
  type CodeGraphConsent,
  type TombstoneMarker,
} from './CodeGraphConsent.js';
import { CodeGraphShardStore, type CodeGraphShardStoreDeps } from './CodeGraphShardStore.js';
import { CodeGraphTombstoneStore, type TombstoneRead } from './CodeGraphTombstoneStore.js';

// Under the 55 s the control plane waits, leaving room for the batch in flight and the final write.
export const CODEBASE_GRAPH_ERASE_BUDGET_MS = 40_000;
const DEFAULT_ERASE_BATCH_SIZE = 64;
const TOMBSTONE_WRITE_ATTEMPTS = 3;

export interface CodeGraphNameStoreDeps extends CodeGraphShardStoreDeps {
  budgetMs?: number;
  batchSize?: number;
  clock?: () => number;
}

interface EraseTarget {
  key: string;
  parsed: ParsedShardKey;
}

interface EraseStart {
  cursor: string;
  isFinished: boolean;
}

/** Retires and overwrites the sealed code-graph names under one org's prefix. */
export class CodeGraphNameStore {
  private readonly tombstones: CodeGraphTombstoneStore;
  private readonly shards: CodeGraphShardStore;
  private readonly budgetMs: number;
  private readonly batchSize: number;
  private readonly clock: () => number;

  constructor(deps: CodeGraphNameStoreDeps) {
    this.tombstones = new CodeGraphTombstoneStore(deps);
    this.shards = new CodeGraphShardStore(deps);
    this.budgetMs = deps.budgetMs ?? CODEBASE_GRAPH_ERASE_BUDGET_MS;
    this.batchSize = deps.batchSize ?? DEFAULT_ERASE_BATCH_SIZE;
    this.clock = deps.clock ?? Date.now;
  }

  async eraseOrg(
    orgId: string,
    retiredGeneration: string,
    currentConsent: () => Promise<CodeGraphConsent>,
    options: { eraseId: string; pass: 1 | 2 },
  ): Promise<CodebaseGraphEraseResponse> {
    const deadline = this.clock() + this.budgetMs;
    try {
      const consent = await this.resolvedConsent(currentConsent);
      this.refuseActiveGeneration(consent, retiredGeneration);
      const passKey = erasePassKey(options.eraseId, options.pass);
      const start = await this.beginErase(orgId, passKey, retiredGeneration, consent);
      if (start.isFinished) return { done: true };
      const targets = await this.pendingTargets(orgId, retiredGeneration, consent, start.cursor);
      return await this.overwriteWithinBudget(orgId, passKey, targets, start, deadline);
    } catch {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
  }

  async readTombstoneMarker(orgId: string): Promise<TombstoneMarker> {
    const read = await this.tombstones.read(orgId);
    if (read.kind === 'missing') return UNRECORDED_TOMBSTONE_MARKER;
    if (read.kind === 'corrupt') {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_TOMBSTONE_UNAVAILABLE);
    }
    return {
      tombstoneId: read.tombstone.tombstoneId,
      allRetiredEpoch: read.tombstone.allRetiredEpoch,
    };
  }

  private async beginErase(
    orgId: string,
    passKey: string,
    retiredGeneration: string,
    consent: CodeGraphConsent,
  ): Promise<EraseStart> {
    for (let attempt = 0; attempt < TOMBSTONE_WRITE_ATTEMPTS; attempt += 1) {
      const read = await this.tombstones.read(orgId);
      const resumed = this.resumedStart(read, passKey, retiredGeneration);
      if (resumed) return resumed;
      const next = await this.startingTombstone(orgId, read, retiredGeneration, consent);
      const etag = read.kind === 'missing' ? null : read.etag;
      if ((await this.tombstones.write(orgId, next, etag)) === 'written') {
        return { cursor: '', isFinished: false };
      }
    }
    throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
  }

  private resumedStart(
    read: TombstoneRead,
    passKey: string,
    retiredGeneration: string,
  ): EraseStart | null {
    if (read.kind !== 'ok') return null;
    const { tombstone } = read;
    if (tombstone.completedErases.includes(passKey)) return { cursor: '', isFinished: true };
    const cursor = tombstone.erasesInProgress[passKey];
    if (cursor !== undefined) return { cursor, isFinished: false };
    const isRecorded =
      retiredGeneration !== ALL_GENERATIONS &&
      tombstone.retiredGenerations.includes(retiredGeneration);
    return isRecorded ? { cursor: '', isFinished: false } : null;
  }

  private async startingTombstone(
    orgId: string,
    read: TombstoneRead,
    retiredGeneration: string,
    consent: CodeGraphConsent,
  ): Promise<CodeGraphTombstone> {
    const base =
      read.kind === 'ok'
        ? read.tombstone
        : read.kind === 'missing'
          ? newTombstone()
          : await this.rebuiltTombstone(orgId, consent);
    return withRetirement(base, retiredGeneration);
  }

  // Repositories are not rebuilt: the fresh tombstone id refuses every merge whose consent marker predates it.
  private async rebuiltTombstone(
    orgId: string,
    consent: CodeGraphConsent,
  ): Promise<CodeGraphTombstone> {
    const generations = await this.groupByGeneration(orgId);
    const rebuilt = newTombstone();
    rebuilt.retiredGenerations = await this.erasedGenerations(orgId, generations, consent);
    return rebuilt;
  }

  private async overwriteWithinBudget(
    orgId: string,
    passKey: string,
    targets: EraseTarget[],
    start: EraseStart,
    deadline: number,
  ): Promise<CodebaseGraphEraseResponse> {
    let cursor = start.cursor;
    let index = 0;
    try {
      while (index < targets.length) {
        const batch = targets.slice(index, index + this.batchSize);
        await this.shards.boundedMap(batch, ({ key, parsed }) =>
          this.shards.overwriteWithErased(orgId, key, parsed),
        );
        index += batch.length;
        cursor = batch[batch.length - 1]?.key ?? cursor;
        if (index < targets.length && this.clock() >= deadline) break;
      }
    } catch (error) {
      await this.keepProgress(orgId, passKey, cursor, start);
      throw error;
    }
    const done = index >= targets.length;
    await this.settleProgress(orgId, passKey, done ? null : cursor);
    return { done };
  }

  private async keepProgress(
    orgId: string,
    passKey: string,
    cursor: string,
    start: EraseStart,
  ): Promise<void> {
    if (cursor === start.cursor) return;
    await this.settleProgress(orgId, passKey, cursor).catch(() => undefined);
  }

  // A null cursor finishes the pass. Both writes are monotonic, so an overlapping call cannot undo them.
  private async settleProgress(
    orgId: string,
    passKey: string,
    cursor: string | null,
  ): Promise<void> {
    for (let attempt = 0; attempt < TOMBSTONE_WRITE_ATTEMPTS; attempt += 1) {
      const read = await this.tombstones.read(orgId);
      if (read.kind !== 'ok')
        throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
      const next =
        cursor === null
          ? withFinishedErase(read.tombstone, passKey)
          : withEraseProgress(read.tombstone, passKey, cursor);
      if (next === read.tombstone) return;
      if ((await this.tombstones.write(orgId, next, read.etag)) === 'written') return;
    }
    throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
  }

  private refuseActiveGeneration(consent: CodeGraphConsent, retiredGeneration: string): void {
    if (consent.active && consent.generation === retiredGeneration) {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
  }

  private async resolvedConsent(
    currentConsent: () => Promise<CodeGraphConsent>,
  ): Promise<CodeGraphConsent> {
    let consent: CodeGraphConsent;
    try {
      consent = await currentConsent();
    } catch {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
    if (!consent.active && consent.reason === 'unresolved') {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
    return consent;
  }

  private async groupByGeneration(orgId: string): Promise<Map<string, string[]>> {
    const groups = new Map<string, string[]>();
    for (const key of await this.shards.listKeys(codeGraphNamesPrefix(orgId))) {
      const { generation } = parseShardKey(orgId, key);
      groups.set(generation, [...(groups.get(generation) ?? []), key]);
    }
    return groups;
  }

  private async erasedGenerations(
    orgId: string,
    generations: Map<string, string[]>,
    consent: CodeGraphConsent,
  ): Promise<string[]> {
    const retired: string[] = [];
    for (const [generation, keys] of generations) {
      if (consent.active && consent.generation === generation) continue;
      if (await this.shards.allErased(orgId, keys)) retired.push(generation);
    }
    return retired;
  }

  private async pendingTargets(
    orgId: string,
    retiredGeneration: string,
    consent: CodeGraphConsent,
    cursor: string,
  ): Promise<EraseTarget[]> {
    const namesPrefix =
      retiredGeneration === ALL_GENERATIONS
        ? codeGraphNamesPrefix(orgId)
        : codeGraphNamesPrefix(orgId, retiredGeneration);
    const names = (await this.shards.listKeys(namesPrefix))
      .map((key) => ({ key, parsed: parseShardKey(orgId, key) }))
      .filter(({ parsed }) => !(consent.active && parsed.generation === consent.generation));
    const quarantine = (await this.shards.listKeys(codeGraphQuarantinePrefix(orgId))).map(
      (key) => ({ key, parsed: parseQuarantineKey(orgId, key) }),
    );
    return [...names, ...quarantine]
      .filter(({ key }) => key > cursor)
      .sort((left, right) => (left.key < right.key ? -1 : 1));
  }
}
