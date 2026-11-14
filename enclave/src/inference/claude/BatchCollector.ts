import { INFERENCE_PURPOSES, type InferencePurpose } from '@folklore/contracts';
import type { Logger } from '@folklore/core';
import type { InferenceUsageEvent } from '@folklore/inference';
import type { LlmOperationCache } from '../vector-cache.js';
import type {
  BatchApiClient,
  BatchProcessingStatus,
  BatchResultLine,
  BatchResultsRead,
} from './BatchApiClient.js';
import type {
  BatchManifest,
  BatchManifestRequest,
  BatchSnapshotAudience,
  CancelPurpose,
} from './batch-manifest.js';
import {
  BatchManifestConflictError,
  type BatchManifestListing,
  type BatchManifestStore,
  type GuardedManifest,
} from './BatchManifestStore.js';
import type { CreatedMessage } from './ClaudeMessagesBackend.js';
import type { PendingBatchRequest } from './BatchRunScope.js';
import {
  BATCH_RESULT_ERASED,
  failureMarker,
  isCreatedMessage,
  resultKeyFor,
} from './batch-keys.js';
import {
  BATCH_ERASE_READ_CUT_LIMIT,
  BATCH_INDEX_RELIST_MS,
  BATCH_MANIFEST_WRITE_ATTEMPTS,
  BATCH_MAX_REQUESTS_PER_SUBMIT,
  BATCH_SETTLES_PER_TOUCH,
  batchResultsBudgetMs,
  batchResultsMaxBytes,
} from './batch-limits.js';
import { batchLog, type BatchResultRefusal } from './batch-log.js';
import { operationOf } from './claude-request.js';
import { CLAUDE_REQUEST_INVALID, ClaudeRouteError } from './claude-route-errors.js';

export type CollectOutcome = 'none' | 'pending' | 'collected';

/** `raced`: another writer holds the manifest (a concurrent delivery wrote first, or the read cannot guard a write); nothing of this call stays open. */
export type SubmitOutcome = 'submitted' | 'already_open' | 'raced' | 'refused';

type BatchApi = Pick<BatchApiClient, 'create' | 'status' | 'results' | 'cancel' | 'delete'>;
type PendingEntry = readonly [string, PendingBatchRequest];
type Disposition = 'keep' | 'close' | 'erase';
type SettleOutcome = 'pending' | 'kept' | 'closed';

// A request the provider refused for what it says will not change on a retry replays as that failure.
const DETERMINISTIC_FAILURES: ReadonlyMap<string, string> = new Map([
  ['invalid_request_error', CLAUDE_REQUEST_INVALID],
  ['request_too_large', CLAUDE_REQUEST_INVALID],
]);
const UNFINISHED: ReadonlySet<BatchProcessingStatus> = new Set(['in_progress', 'canceling']);

export interface BatchCollectorDeps {
  readonly api: BatchApi;
  readonly manifests: (orgId: string) => BatchManifestStore;
  readonly results: (orgId: string) => LlmOperationCache;
  readonly allowedModels: readonly string[];
  readonly allows: (orgId: string) => boolean;
  readonly recordUsage: (orgId: string, event: InferenceUsageEvent) => void;
  readonly logger: Logger;
  readonly now?: () => number;
}

interface Collected {
  readonly sealedIds: string[];
  readonly usage: InferenceUsageEvent[];
  refused: number;
}

interface HarvestMode {
  readonly keep: boolean;
  readonly signal: AbortSignal | undefined;
  readonly unread: boolean;
}

interface KnownBatches {
  readonly unclosed: Set<string>;
  readonly open: Set<string>;
  readonly retiring: Set<string>;
  readonly orphans: Map<string, BatchManifest>;
  complete: boolean;
  listedAtMs: number;
}

interface UnclosedRead {
  readonly manifests: BatchManifest[];
  readonly failure: unknown;
}

/** Submits one batch per org per wiki request, collects its results into the org's sealed store, and cancels what is open. */
export class BatchCollector {
  private readonly knownByOrg = new Map<string, KnownBatches>();
  private readonly listings = new Map<string, Promise<KnownBatches>>();
  // Ids added while an org's listing runs, which that listing's snapshot cannot have seen and so must not remove.
  private readonly addedDuringListing = new Map<string, Set<string>>();
  // One harvest per batch at a time in this process; across processes only the caller whose DELETE succeeds meters.
  private readonly harvesting = new Set<string>();
  // In process only: a restart forgets it, and an erase then needs the full number of cut passes again.
  private readonly readCuts = new Map<string, number>();

  constructor(private readonly deps: BatchCollectorDeps) {}

  async collect(
    orgId: string,
    wikiRequestId: string,
    signal?: AbortSignal,
  ): Promise<CollectOutcome> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest === undefined || manifest.closed || manifest.open === undefined) return 'none';
    const erasing =
      manifest.open.cancelRequested === true && !BatchCollector.keepsResults(manifest);
    const outcome = await this.settleOrDefer(manifest, erasing ? 'erase' : 'keep', signal);
    if (outcome === 'pending') return 'pending';
    return outcome === 'closed' ? 'none' : 'collected';
  }

  async submit(
    orgId: string,
    wikiRequestId: string,
    pending: ReadonlyMap<string, PendingBatchRequest>,
    snapshot: readonly BatchSnapshotAudience[],
  ): Promise<SubmitOutcome> {
    const entries = [...pending].slice(0, BATCH_MAX_REQUESTS_PER_SUBMIT);
    this.assertAllowedModels(entries.map(([, entry]) => entry));
    const store = this.deps.manifests(orgId);
    const basis = await store.readGuarded(wikiRequestId);
    const prior = basis.manifest?.closed === true ? undefined : basis.manifest;
    if (prior?.open !== undefined) return 'already_open';
    if (!this.deps.allows(orgId)) return 'refused';
    if (!store.canGuard(basis)) return 'raced';
    const known = await this.known(orgId);
    const batchId = await this.deps.api.create(
      entries.map(([customId, entry]) => ({ custom_id: customId, params: entry.request })),
    );
    const opened = this.opened(orgId, wikiRequestId, prior, batchId, entries, snapshot);
    try {
      await this.keepOrCancel(store, batchId, opened, basis);
    } catch (error) {
      if (!(error instanceof BatchManifestConflictError)) throw error;
      known.orphans.set(batchId, BatchCollector.cancelled(opened, 'discard'));
      return 'raced';
    }
    this.add(orgId, known.unclosed, wikiRequestId);
    this.add(orgId, known.open, wikiRequestId);
    if (this.deps.allows(orgId)) return 'submitted';
    await this.retire(opened, undefined);
    return 'refused';
  }

  /** Returns how many of the org's batches are still retiring, cancelled but not yet ended and deleted. */
  async cancelAll(orgId: string, signal?: AbortSignal): Promise<number> {
    const read = await this.readUnclosed(orgId, await this.known(orgId), signal);
    let retiring = 0;
    let { failure } = read;
    for (const manifest of this.byCutCount(read.manifests)) {
      if (signal?.aborted === true) {
        failure ??= signal.reason;
        break;
      }
      try {
        if (!(await this.retire(manifest, signal, true))) retiring += 1;
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure !== undefined) throw failure;
    return retiring;
  }

  private async readUnclosed(
    orgId: string,
    known: KnownBatches,
    signal: AbortSignal | undefined,
  ): Promise<UnclosedRead> {
    const store = this.deps.manifests(orgId);
    const manifests: BatchManifest[] = [];
    let failure: unknown;
    for (const wikiRequestId of [...known.unclosed]) {
      if (signal?.aborted === true) {
        failure ??= signal.reason;
        break;
      }
      try {
        const manifest = await store.read(wikiRequestId);
        if (manifest === undefined || manifest.closed) this.forget(orgId, wikiRequestId, true);
        else manifests.push(manifest);
      } catch (error) {
        failure ??= error;
      }
    }
    return { manifests, failure };
  }

  /** Settles a bounded number of the cancelled batches, and lost-race orphans, this process knows the org has. */
  async settleRetiring(
    orgId: string,
    exceptRequestId?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const known = this.knownByOrg.get(orgId);
    if (known === undefined) return;
    const due = [...known.retiring].filter((id) => id !== exceptRequestId);
    const settling = due.slice(0, BATCH_SETTLES_PER_TOUCH);
    for (const wikiRequestId of settling)
      await this.settleOne(orgId, wikiRequestId, known.retiring, signal);
    const orphans = [...known.orphans].slice(0, BATCH_SETTLES_PER_TOUCH - settling.length);
    for (const [batchId, manifest] of orphans) {
      await this.settleOrphan(known, batchId, manifest, signal);
    }
  }

  /** Records a cancel without calling the API, for a settle to send once the batch key is back. */
  async deferCancel(
    orgId: string,
    wikiRequestId: string,
    purpose: CancelPurpose = 'drain',
  ): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest !== undefined && !manifest.closed) await this.recordCancel(manifest, purpose);
  }

  async abandon(orgId: string, wikiRequestId: string, signal?: AbortSignal): Promise<void> {
    await this.discard(orgId, wikiRequestId, signal);
  }

  /** Cancels the request's batch and erases what it sealed; true when nothing of it is left at the provider. */
  async discard(orgId: string, wikiRequestId: string, signal?: AbortSignal): Promise<boolean> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest === undefined || manifest.closed) return true;
    // 'kept' means another writer opened a new batch meanwhile, which this discard has not cancelled.
    return (await this.retireOutcome(manifest, signal)) === 'closed';
  }

  async stopBatch(orgId: string, wikiRequestId: string): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest !== undefined && !manifest.closed) await this.requestCancel(manifest, 'drain');
  }

  // A finished run needs nothing a stopped batch still holds, so a stop recorded for a drain becomes a discard.
  async finish(orgId: string, wikiRequestId: string, signal?: AbortSignal): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest === undefined || manifest.closed) return;
    if (manifest.open?.cancelRequested === true) await this.retire(manifest, signal);
    else await this.settle(manifest, 'close', signal);
  }

  async openCount(orgId: string): Promise<number> {
    return (await this.known(orgId)).open.size;
  }

  private async settleOne(
    orgId: string,
    wikiRequestId: string,
    retiring: Set<string>,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    retiring.delete(wikiRequestId);
    try {
      const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
      if (!BatchCollector.isRetiring(manifest)) return;
      const outcome = await this.settle(manifest, BatchCollector.dispositionOf(manifest), signal);
      if (outcome === 'pending') retiring.add(wikiRequestId);
    } catch (error) {
      retiring.add(wikiRequestId);
      throw error;
    }
  }

  // A lost race's batch is metered and deleted but never sealed, so no erasure has to find its results.
  private async settleOrphan(
    known: KnownBatches,
    batchId: string,
    manifest: BatchManifest,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    known.orphans.delete(batchId);
    try {
      const harvested = await this.harvest(manifest, batchId, {
        keep: false,
        signal,
        unread: false,
      });
      if (harvested === undefined) known.orphans.set(batchId, manifest);
    } catch (error) {
      known.orphans.set(batchId, manifest);
      throw error;
    }
  }

  private static cancelled(manifest: BatchManifest, purpose: CancelPurpose): BatchManifest {
    if (manifest.open === undefined) return manifest;
    return {
      ...manifest,
      open: { ...manifest.open, cancelRequested: true, cancelPurpose: purpose },
    };
  }

  // A cancel recorded without a purpose is read as a discard, the stricter reading.
  private static keepsResults(manifest: BatchManifest): boolean {
    return manifest.open?.cancelPurpose === 'drain';
  }

  private static dispositionOf(manifest: BatchManifest): Disposition {
    return BatchCollector.keepsResults(manifest) ? 'keep' : 'erase';
  }

  private static isStopped(manifest: BatchManifest, purpose: CancelPurpose): boolean {
    const { open } = manifest;
    if (open?.cancelRequested !== true) return false;
    return purpose === 'drain' || open.cancelPurpose !== 'drain';
  }

  private static isRetiring(manifest: BatchManifest | undefined): manifest is BatchManifest {
    return manifest?.closed === false && manifest.open?.cancelRequested === true;
  }

  private opened(
    orgId: string,
    wikiRequestId: string,
    prior: BatchManifest | undefined,
    batchId: string,
    entries: readonly PendingEntry[],
    snapshot: readonly BatchSnapshotAudience[],
  ): BatchManifest {
    return {
      v: 1,
      orgId,
      wikiRequestId,
      closed: false,
      rounds: (prior?.rounds ?? 0) + 1,
      startedAtMs: prior?.startedAtMs ?? this.now(),
      open: {
        batchId,
        requests: entries.map(([customId, entry]) => this.entryOf(customId, entry)),
      },
      resultIds: prior?.resultIds ?? [],
      ...(prior?.refusedResults === undefined ? {} : { refusedResults: prior.refusedResults }),
      snapshot: prior?.snapshot ?? [...snapshot],
    };
  }

  private entryOf(customId: string, entry: PendingBatchRequest): BatchManifestRequest {
    const { model, purpose, request } = entry;
    return { customId, model, purpose, operation: operationOf(request) };
  }

  private async retire(
    manifest: BatchManifest,
    signal: AbortSignal | undefined,
    unreadAllowed = false,
  ): Promise<boolean> {
    return (await this.retireOutcome(manifest, signal, unreadAllowed)) !== 'pending';
  }

  private async retireOutcome(
    manifest: BatchManifest,
    signal: AbortSignal | undefined,
    unreadAllowed = false,
  ): Promise<SettleOutcome> {
    const cancelled = await this.requestCancel(manifest, 'discard');
    return this.settle(cancelled, 'erase', signal, unreadAllowed);
  }

  private async requestCancel(
    manifest: BatchManifest,
    purpose: CancelPurpose,
  ): Promise<BatchManifest> {
    if (manifest.open === undefined || BatchCollector.isStopped(manifest, purpose)) return manifest;
    if (manifest.open.cancelRequested !== true) await this.deps.api.cancel(manifest.open.batchId);
    return this.recordCancel(manifest, purpose);
  }

  private async recordCancel(
    manifest: BatchManifest,
    purpose: CancelPurpose,
  ): Promise<BatchManifest> {
    const { orgId, wikiRequestId } = manifest;
    if (manifest.open === undefined || BatchCollector.isStopped(manifest, purpose)) return manifest;
    const requested = await this.rewrite(orgId, wikiRequestId, async (current) =>
      current.closed || BatchCollector.isStopped(current, purpose)
        ? undefined
        : BatchCollector.cancelled(current, purpose),
    );
    if (requested === undefined) return manifest;
    const known = this.indexFor(orgId);
    this.add(orgId, known.unclosed, wikiRequestId);
    this.add(orgId, known.retiring, wikiRequestId);
    return requested;
  }

  // A conflict on the collect path is left for the next poll, which finds the batch already gone.
  private async settleOrDefer(
    manifest: BatchManifest,
    disposition: Disposition,
    signal: AbortSignal | undefined,
  ): Promise<SettleOutcome> {
    try {
      return await this.settle(manifest, disposition, signal);
    } catch (error) {
      if (!(error instanceof BatchManifestConflictError)) throw error;
      this.deps.logger.warn(...batchLog.collectConflict(manifest.orgId));
      return 'pending';
    }
  }

  // A batch still ending is left for the next pass; `keep` leaves the manifest open with what the batch paid for.
  private async settle(
    manifest: BatchManifest,
    disposition: Disposition,
    signal: AbortSignal | undefined,
    unreadAllowed = false,
  ): Promise<SettleOutcome> {
    const { orgId, wikiRequestId } = manifest;
    const batchId = manifest.open?.batchId;
    const collected =
      batchId === undefined
        ? BatchCollector.empty()
        : await this.harvest(manifest, batchId, {
            keep: true,
            signal,
            unread: unreadAllowed && this.isWorn(batchId),
          });
    if (collected === undefined) return 'pending';
    let seen: BatchManifest | undefined;
    const written = await this.rewrite(orgId, wikiRequestId, async (current) => {
      seen = current;
      return this.settledFrom(current, batchId, collected, disposition);
    });
    const settled = written ?? seen;
    if (settled?.open === undefined) this.forget(orgId, wikiRequestId, settled?.closed === true);
    if (settled?.closed === false) this.add(orgId, this.indexFor(orgId).unclosed, wikiRequestId);
    return settled?.closed === true ? 'closed' : 'kept';
  }

  // The fresh manifest decides: a discard or a settle by another writer outranks what this call asked for.
  private async settledFrom(
    current: BatchManifest,
    harvestedBatchId: string | undefined,
    collected: Collected,
    disposition: Disposition,
  ): Promise<BatchManifest | undefined> {
    if (current.closed || current.open?.batchId !== harvestedBatchId) {
      await this.eraseUnreferenced(current, collected.sealedIds);
      return undefined;
    }
    const discarded =
      current.open?.cancelRequested === true && !BatchCollector.keepsResults(current);
    const effective = discarded ? 'erase' : disposition;
    if (effective === 'erase') await this.erase(current);
    return BatchCollector.settled(current, collected, effective);
  }

  private async eraseUnreferenced(current: BatchManifest, ids: readonly string[]): Promise<void> {
    const referenced = new Set([...current.resultIds, ...BatchCollector.requestIds(current)]);
    await this.eraseIds(
      current.orgId,
      ids.filter((id) => !referenced.has(id)),
    );
  }

  private async rewrite(
    orgId: string,
    wikiRequestId: string,
    next: (current: BatchManifest) => Promise<BatchManifest | undefined>,
  ): Promise<BatchManifest | undefined> {
    const store = this.deps.manifests(orgId);
    for (let attempt = 0; attempt < BATCH_MANIFEST_WRITE_ATTEMPTS; attempt += 1) {
      const basis = await store.readGuarded(wikiRequestId);
      if (basis.manifest === undefined || !store.canGuard(basis)) continue;
      const written = await next(basis.manifest);
      if (written === undefined) return undefined;
      try {
        await store.write(written, basis);
        return written;
      } catch (error) {
        if (!(error instanceof BatchManifestConflictError)) throw error;
      }
    }
    throw new BatchManifestConflictError();
  }

  private static settled(
    manifest: BatchManifest,
    collected: Collected,
    disposition: Disposition,
  ): BatchManifest {
    if (disposition === 'keep') {
      const resultIds = [...manifest.resultIds, ...collected.sealedIds];
      const refused = (manifest.refusedResults ?? 0) + collected.refused;
      return {
        ...manifest,
        open: undefined,
        resultIds,
        ...(refused > 0 ? { refusedResults: refused } : {}),
      };
    }
    return { ...manifest, closed: true, open: undefined, resultIds: [], snapshot: [] };
  }

  private async harvest(
    manifest: BatchManifest,
    batchId: string,
    mode: HarvestMode,
  ): Promise<Collected | undefined> {
    if (this.harvesting.has(batchId)) return undefined;
    this.harvesting.add(batchId);
    try {
      return mode.unread
        ? await this.dropUnread(manifest, batchId)
        : await this.harvestClaimed(manifest, batchId, mode);
    } finally {
      this.harvesting.delete(batchId);
    }
  }

  // Requests that finished before a cancel were paid for, so an ended batch is always read before its DELETE.
  private async harvestClaimed(
    manifest: BatchManifest,
    batchId: string,
    mode: HarvestMode,
  ): Promise<Collected | undefined> {
    const status = await this.deps.api.status(batchId);
    if (UNFINISHED.has(status)) return this.stillRunning(manifest, batchId, status);
    if (status === 'gone') return this.gone(manifest, batchId, mode.keep);
    const collected = await this.seal(manifest, mode);
    this.readCuts.delete(batchId);
    const deleted = await this.deps.api.delete(batchId);
    if (deleted === 'refused') return undefined;
    if (deleted === 'deleted')
      collected.usage.forEach((event) => this.deps.recordUsage(manifest.orgId, event));
    return collected;
  }

  // An ended batch is deleted without a read once an opt-out has been cut off its results often enough; its usage is not metered.
  private async dropUnread(
    manifest: BatchManifest,
    batchId: string,
  ): Promise<Collected | undefined> {
    const status = await this.deps.api.status(batchId);
    if (UNFINISHED.has(status)) return this.stillRunning(manifest, batchId, status);
    if (status === 'gone') return this.gone(manifest, batchId, false);
    const deleted = await this.deps.api.delete(batchId);
    if (deleted === 'refused') return undefined;
    this.readCuts.delete(batchId);
    if (deleted === 'deleted') this.deps.logger.warn(...batchLog.deletedUnread(manifest.orgId));
    return BatchCollector.empty();
  }

  private gone(manifest: BatchManifest, batchId: string, keep: boolean): Collected {
    this.readCuts.delete(batchId);
    return BatchCollector.goneBatch(manifest, keep);
  }

  private isWorn(batchId: string): boolean {
    return (this.readCuts.get(batchId) ?? 0) >= BATCH_ERASE_READ_CUT_LIMIT;
  }

  // Batches already at the cut limit need no read, then those never cut, then those cut before: a slow body is last.
  private byCutCount(manifests: readonly BatchManifest[]): BatchManifest[] {
    const rank = (manifest: BatchManifest): number => {
      const batchId = manifest.open?.batchId ?? '';
      if (this.isWorn(batchId)) return 0;
      return this.readCuts.has(batchId) ? 2 : 1;
    };
    return [...manifests].sort((left, right) => rank(left) - rank(right));
  }

  // A cancel recorded while the batch key was out reaches the provider on the next pass.
  private async stillRunning(
    manifest: BatchManifest,
    batchId: string,
    status: BatchProcessingStatus,
  ): Promise<undefined> {
    if (status === 'in_progress' && manifest.open?.cancelRequested === true) {
      await this.deps.api.cancel(batchId);
    }
    return undefined;
  }

  private async erase(manifest: BatchManifest): Promise<void> {
    await this.eraseIds(manifest.orgId, [
      ...manifest.resultIds,
      ...BatchCollector.requestIds(manifest),
    ]);
  }

  private async eraseIds(orgId: string, ids: readonly string[]): Promise<void> {
    const store = this.deps.results(orgId);
    for (const id of ids) await store.set(resultKeyFor(id), BATCH_RESULT_ERASED);
  }

  private async seal(manifest: BatchManifest, mode: HarvestMode): Promise<Collected> {
    const { keep } = mode;
    const requests = manifest.open?.requests ?? [];
    const expected = new Map(requests.map((entry) => [entry.customId, entry]));
    const store = this.deps.results(manifest.orgId);
    const collected = BatchCollector.empty();
    const batchId = manifest.open?.batchId ?? '';
    const lines = this.deps.api.results(
      batchId,
      this.readOf(requests.length, batchId, mode.signal, collected),
    );
    for await (const line of lines) {
      const entry = expected.get(line.customId);
      if (entry === undefined) {
        this.refuse('foreign_id', collected);
        continue;
      }
      const sealed = this.sealedFor(line, entry.model, collected);
      if (sealed === undefined) continue;
      if (keep) {
        await store.set(resultKeyFor(line.customId), sealed.value);
        collected.sealedIds.push(line.customId);
      }
      if (sealed.usage !== undefined) collected.usage.push(this.usageOf(entry, sealed.usage));
    }
    return collected;
  }

  private readOf(
    requests: number,
    batchId: string,
    signal: AbortSignal | undefined,
    collected: Collected,
  ): BatchResultsRead {
    return {
      maxBytes: batchResultsMaxBytes(requests),
      budgetMs: batchResultsBudgetMs(requests),
      ...(signal === undefined ? {} : { signal }),
      onRefused: (reason) => void this.refuse(reason, collected),
      onCut: () => this.readCuts.set(batchId, (this.readCuts.get(batchId) ?? 0) + 1),
    };
  }

  private sealedFor(
    line: BatchResultLine,
    expectedModel: string,
    collected: Collected,
  ): { value: string; usage?: CreatedMessage['usage'] } | undefined {
    if (line.outcome !== 'succeeded') return this.sealedFailure(line);
    if (!isCreatedMessage(line.message)) return this.refuse('malformed', collected);
    if (line.message.model !== expectedModel) return this.refuse('model_mismatch', collected);
    const { usage } = line.message;
    if (!BatchCollector.isSound(usage)) return this.refuse('usage_invalid', collected);
    return { value: JSON.stringify(line.message), usage };
  }

  private sealedFailure(line: BatchResultLine): { value: string } | undefined {
    const type = line.outcome === 'errored' ? line.errorType : line.outcome;
    this.deps.logger.warn(...batchLog.resultErrored(type));
    const code = line.outcome === 'errored' ? DETERMINISTIC_FAILURES.get(type) : undefined;
    return code === undefined ? undefined : { value: failureMarker(code) };
  }

  private refuse(reason: BatchResultRefusal, collected: Collected): undefined {
    collected.refused += 1;
    this.deps.logger.warn(...batchLog.resultRefused(reason));
    return undefined;
  }

  private assertAllowedModels(entries: readonly PendingBatchRequest[]): void {
    if (entries.some((entry) => !this.deps.allowedModels.includes(entry.model))) {
      throw new ClaudeRouteError('claude_model_not_allowed');
    }
  }

  // A batch whose manifest cannot be written, or lost a race to another delivery, is cancelled so nothing it returns is orphaned.
  private async keepOrCancel(
    store: BatchManifestStore,
    batchId: string,
    manifest: BatchManifest,
    basis: GuardedManifest,
  ): Promise<void> {
    try {
      await store.write(manifest, basis);
    } catch (error) {
      await this.deps.api.cancel(batchId).catch(() => undefined);
      throw error;
    }
  }

  private usageOf(
    entry: BatchManifestRequest,
    usage: CreatedMessage['usage'],
  ): InferenceUsageEvent {
    const written = usage.cache_creation_input_tokens ?? 0;
    // Every batched prefix asks for a one-hour entry, so a write without a split is all one-hour.
    const oneHour = usage.cache_creation?.ephemeral_1h_input_tokens ?? written;
    return {
      model: entry.model,
      operation: entry.operation,
      promptTokens: usage.input_tokens,
      completionTokens: usage.output_tokens,
      cached: false,
      purpose: (INFERENCE_PURPOSES as readonly string[]).includes(entry.purpose)
        ? (entry.purpose as InferencePurpose)
        : 'untagged',
      outcome: 'ok',
      cacheReadTokens: usage.cache_read_input_tokens ?? 0,
      cacheWriteTokens: written - oneHour,
      cacheWrite1hTokens: oneHour,
    };
  }

  private static empty(): Collected {
    return { sealedIds: [], usage: [], refused: 0 };
  }

  // Another caller may have sealed a deleted batch without recording it, so a kept one claims every request id.
  private static goneBatch(manifest: BatchManifest, keep: boolean): Collected {
    return {
      sealedIds: keep ? BatchCollector.requestIds(manifest) : [],
      usage: [],
      refused: 0,
    };
  }

  private static requestIds(manifest: BatchManifest): string[] {
    return manifest.open?.requests.map((request) => request.customId) ?? [];
  }

  private static isSound(usage: CreatedMessage['usage']): boolean {
    const written = usage.cache_creation_input_tokens ?? 0;
    const counts = [
      usage.input_tokens,
      usage.output_tokens,
      usage.cache_read_input_tokens ?? 0,
      written,
      usage.cache_creation?.ephemeral_1h_input_tokens ?? 0,
    ];
    const whole = counts.every((value) => Number.isSafeInteger(value) && value >= 0);
    return whole && (usage.cache_creation?.ephemeral_1h_input_tokens ?? 0) <= written;
  }

  private async known(orgId: string): Promise<KnownBatches> {
    const known = this.indexFor(orgId);
    if (known.complete && this.now() - known.listedAtMs < BATCH_INDEX_RELIST_MS) return known;
    return this.listings.get(orgId) ?? this.startListing(orgId, known);
  }

  private indexFor(orgId: string): KnownBatches {
    const held = this.knownByOrg.get(orgId);
    if (held !== undefined) return held;
    const created: KnownBatches = {
      unclosed: new Set(),
      open: new Set(),
      retiring: new Set(),
      orphans: new Map(),
      complete: false,
      listedAtMs: 0,
    };
    this.knownByOrg.set(orgId, created);
    return created;
  }

  private startListing(orgId: string, known: KnownBatches): Promise<KnownBatches> {
    const listing = this.list(orgId, known);
    this.listings.set(orgId, listing);
    return listing;
  }

  private async list(orgId: string, known: KnownBatches): Promise<KnownBatches> {
    this.addedDuringListing.set(orgId, new Set());
    try {
      const startedAtMs = this.now();
      const listing = await this.deps.manifests(orgId).listing();
      this.merge(orgId, known, listing);
      known.complete = listing.complete;
      known.listedAtMs = startedAtMs;
      return known;
    } finally {
      this.listings.delete(orgId);
      this.addedDuringListing.delete(orgId);
    }
  }

  // Only a complete listing may remove an id, and never one added after the listing began.
  private merge(orgId: string, known: KnownBatches, listing: BatchManifestListing): void {
    const withBatch = listing.unclosed.filter((manifest) => manifest.open !== undefined);
    const retiring = withBatch.filter((manifest) => manifest.open?.cancelRequested === true);
    const found: readonly [Set<string>, readonly BatchManifest[]][] = [
      [known.unclosed, listing.unclosed],
      [known.open, withBatch],
      [known.retiring, retiring],
    ];
    for (const [held, listed] of found) {
      const ids = new Set(listed.map((manifest) => manifest.wikiRequestId));
      if (listing.complete) this.prune(orgId, held, ids);
      ids.forEach((id) => held.add(id));
    }
  }

  private prune(orgId: string, held: Set<string>, listed: ReadonlySet<string>): void {
    const added = this.addedDuringListing.get(orgId);
    for (const id of [...held]) if (!listed.has(id) && added?.has(id) !== true) held.delete(id);
  }

  private add(orgId: string, held: Set<string>, wikiRequestId: string): void {
    held.add(wikiRequestId);
    this.addedDuringListing.get(orgId)?.add(wikiRequestId);
  }

  private forget(orgId: string, wikiRequestId: string, closed: boolean): void {
    const known = this.knownByOrg.get(orgId);
    known?.open.delete(wikiRequestId);
    known?.retiring.delete(wikiRequestId);
    if (closed) known?.unclosed.delete(wikiRequestId);
  }

  private now(): number {
    return this.deps.now?.() ?? Date.now();
  }
}
