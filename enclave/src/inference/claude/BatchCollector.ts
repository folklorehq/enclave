import { INFERENCE_PURPOSES, type InferencePurpose } from '@folklore/contracts';
import type { Logger } from '@folklore/core';
import type { InferenceUsageEvent } from '@folklore/inference';
import type { LlmOperationCache } from '../vector-cache.js';
import type { BatchApiClient, BatchProcessingStatus, BatchResultLine } from './BatchApiClient.js';
import type {
  BatchManifest,
  BatchManifestRequest,
  BatchSnapshotAudience,
  CancelPurpose,
} from './batch-manifest.js';
import {
  BatchManifestConflictError,
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
import { BATCH_MAX_REQUESTS_PER_SUBMIT, BATCH_SETTLES_PER_TOUCH } from './batch-limits.js';
import { batchLog, type BatchResultRefusal } from './batch-log.js';
import { operationOf } from './claude-request.js';
import { CLAUDE_REQUEST_INVALID, ClaudeRouteError } from './claude-route-errors.js';

export type CollectOutcome = 'none' | 'pending' | 'collected';

/** `raced`: another writer holds the manifest (a concurrent delivery wrote first, or the read cannot guard a write); nothing of this call stays open. */
export type SubmitOutcome = 'submitted' | 'already_open' | 'raced' | 'refused';

type BatchApi = Pick<BatchApiClient, 'create' | 'status' | 'results' | 'cancel' | 'delete'>;
type PendingEntry = readonly [string, PendingBatchRequest];
type Disposition = 'keep' | 'close' | 'erase';

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
}

interface KnownBatches {
  readonly open: Set<string>;
  readonly retiring: Set<string>;
  readonly orphans: Map<string, BatchManifest>;
}

/** Submits one batch per org per wiki request, collects its results into the org's sealed store, and cancels what is open. */
export class BatchCollector {
  private readonly knownByOrg = new Map<string, KnownBatches>();
  // One harvest per batch at a time in this process; across processes only the caller whose DELETE succeeds meters.
  private readonly harvesting = new Set<string>();

  constructor(private readonly deps: BatchCollectorDeps) {}

  async collect(orgId: string, wikiRequestId: string): Promise<CollectOutcome> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest === undefined || manifest.closed || manifest.open === undefined) return 'none';
    if (manifest.open.cancelRequested === true && !BatchCollector.keepsResults(manifest)) {
      return (await this.settle(manifest, 'erase')) ? 'none' : 'pending';
    }
    const collected = await this.harvest(manifest, manifest.open.batchId);
    if (collected === undefined) return 'pending';
    await this.deps.manifests(orgId).write({
      ...manifest,
      open: undefined,
      resultIds: [...manifest.resultIds, ...collected.sealedIds],
    });
    this.forget(orgId, wikiRequestId);
    return 'collected';
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
    const batchId = await this.deps.api.create(
      entries.map(([customId, entry]) => ({ custom_id: customId, params: entry.request })),
    );
    const opened = this.opened(orgId, wikiRequestId, prior, batchId, entries, snapshot);
    try {
      await this.keepOrCancel(store, batchId, opened, basis);
    } catch (error) {
      if (!(error instanceof BatchManifestConflictError)) throw error;
      (await this.known(orgId)).orphans.set(batchId, BatchCollector.cancelled(opened, 'discard'));
      return 'raced';
    }
    (await this.known(orgId)).open.add(wikiRequestId);
    return 'submitted';
  }

  /** Returns how many of the org's batches are still retiring, cancelled but not yet ended and deleted. */
  async cancelAll(orgId: string): Promise<number> {
    let retiring = 0;
    let failure: unknown;
    for (const manifest of await this.deps.manifests(orgId).listOpen()) {
      try {
        if (!(await this.retire(manifest))) retiring += 1;
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure !== undefined) throw failure;
    return retiring;
  }

  /** Settles a bounded number of the cancelled batches, and lost-race orphans, this process knows the org has. */
  async settleRetiring(orgId: string, exceptRequestId?: string): Promise<void> {
    const known = this.knownByOrg.get(orgId);
    if (known === undefined) return;
    const due = [...known.retiring].filter((id) => id !== exceptRequestId);
    const settling = due.slice(0, BATCH_SETTLES_PER_TOUCH);
    for (const wikiRequestId of settling)
      await this.settleOne(orgId, wikiRequestId, known.retiring);
    const orphans = [...known.orphans].slice(0, BATCH_SETTLES_PER_TOUCH - settling.length);
    for (const [batchId, manifest] of orphans) await this.settleOrphan(known, batchId, manifest);
  }

  /** Records a cancel without calling the API, for a settle to send once the batch key is back. */
  async deferCancel(orgId: string, wikiRequestId: string): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest !== undefined && !manifest.closed) await this.recordCancel(manifest, 'drain');
  }

  async abandon(orgId: string, wikiRequestId: string): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest !== undefined && !manifest.closed) await this.retire(manifest);
  }

  async stopBatch(orgId: string, wikiRequestId: string): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest !== undefined && !manifest.closed) await this.requestCancel(manifest, 'drain');
  }

  // A finished run needs nothing a stopped batch still holds, so a stop recorded for a drain becomes a discard.
  async finish(orgId: string, wikiRequestId: string): Promise<void> {
    const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
    if (manifest === undefined || manifest.closed) return;
    if (manifest.open?.cancelRequested === true) await this.retire(manifest);
    else await this.settle(manifest, 'close');
  }

  async openCount(orgId: string): Promise<number> {
    return (await this.known(orgId)).open.size;
  }

  private async settleOne(
    orgId: string,
    wikiRequestId: string,
    retiring: Set<string>,
  ): Promise<void> {
    retiring.delete(wikiRequestId);
    try {
      const manifest = await this.deps.manifests(orgId).read(wikiRequestId);
      if (!BatchCollector.isRetiring(manifest)) return;
      if (!(await this.settle(manifest, BatchCollector.dispositionOf(manifest)))) {
        retiring.add(wikiRequestId);
      }
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
  ): Promise<void> {
    known.orphans.delete(batchId);
    try {
      const harvested = await this.harvest(manifest, batchId, false);
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
      snapshot: prior?.snapshot ?? [...snapshot],
    };
  }

  private entryOf(customId: string, entry: PendingBatchRequest): BatchManifestRequest {
    const { model, purpose, request } = entry;
    return { customId, model, purpose, operation: operationOf(request) };
  }

  private async retire(manifest: BatchManifest): Promise<boolean> {
    return this.settle(await this.requestCancel(manifest, 'discard'), 'erase');
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
    if (manifest.open === undefined || BatchCollector.isStopped(manifest, purpose)) return manifest;
    const requested = BatchCollector.cancelled(manifest, purpose);
    await this.deps.manifests(manifest.orgId).write(requested);
    (await this.known(manifest.orgId)).retiring.add(manifest.wikiRequestId);
    return requested;
  }

  // A batch still ending is left for the next pass; `keep` leaves the manifest open with what the batch paid for.
  private async settle(manifest: BatchManifest, disposition: Disposition): Promise<boolean> {
    const batchId = manifest.open?.batchId;
    const collected =
      batchId === undefined ? BatchCollector.empty() : await this.harvest(manifest, batchId);
    if (collected === undefined) return false;
    if (disposition === 'erase') await this.erase(manifest);
    await this.deps
      .manifests(manifest.orgId)
      .write(BatchCollector.settled(manifest, collected, disposition));
    this.forget(manifest.orgId, manifest.wikiRequestId);
    return true;
  }

  private static settled(
    manifest: BatchManifest,
    collected: Collected,
    disposition: Disposition,
  ): BatchManifest {
    if (disposition === 'keep') {
      const resultIds = [...manifest.resultIds, ...collected.sealedIds];
      return { ...manifest, open: undefined, resultIds };
    }
    return { ...manifest, closed: true, open: undefined, resultIds: [], snapshot: [] };
  }

  private async harvest(
    manifest: BatchManifest,
    batchId: string,
    keep = true,
  ): Promise<Collected | undefined> {
    if (this.harvesting.has(batchId)) return undefined;
    this.harvesting.add(batchId);
    try {
      return await this.harvestClaimed(manifest, batchId, keep);
    } finally {
      this.harvesting.delete(batchId);
    }
  }

  // Requests that finished before a cancel were paid for, so an ended batch is always read before its DELETE.
  private async harvestClaimed(
    manifest: BatchManifest,
    batchId: string,
    keep: boolean,
  ): Promise<Collected | undefined> {
    const status = await this.deps.api.status(batchId);
    if (UNFINISHED.has(status)) return this.stillRunning(manifest, batchId, status);
    if (status === 'gone') return BatchCollector.empty();
    const collected = await this.seal(manifest.orgId, manifest, keep);
    const deleted = await this.deps.api.delete(batchId);
    if (deleted === 'refused') return undefined;
    if (deleted === 'deleted')
      collected.usage.forEach((event) => this.deps.recordUsage(manifest.orgId, event));
    return collected;
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
    const store = this.deps.results(manifest.orgId);
    const ids = [...manifest.resultIds, ...(manifest.open?.requests.map((r) => r.customId) ?? [])];
    for (const id of ids) await store.set(resultKeyFor(id), BATCH_RESULT_ERASED);
  }

  private async seal(orgId: string, manifest: BatchManifest, keep: boolean): Promise<Collected> {
    const expected = new Map(manifest.open?.requests.map((entry) => [entry.customId, entry]));
    const store = this.deps.results(orgId);
    const collected = BatchCollector.empty();
    for (const line of await this.deps.api.results(manifest.open?.batchId ?? '')) {
      const entry = expected.get(line.customId);
      if (entry === undefined) {
        this.refuse('foreign_id');
        continue;
      }
      const sealed = this.sealedFor(line, entry.model);
      if (sealed === undefined) continue;
      if (keep) {
        await store.set(resultKeyFor(line.customId), sealed.value);
        collected.sealedIds.push(line.customId);
      }
      if (sealed.usage !== undefined) collected.usage.push(this.usageOf(entry, sealed.usage));
    }
    return collected;
  }

  private sealedFor(
    line: BatchResultLine,
    expectedModel: string,
  ): { value: string; usage?: CreatedMessage['usage'] } | undefined {
    if (line.outcome !== 'succeeded') return this.sealedFailure(line);
    if (!isCreatedMessage(line.message)) return this.refuse('malformed');
    if (line.message.model !== expectedModel) return this.refuse('model_mismatch');
    const { usage } = line.message;
    if (!BatchCollector.isSound(usage)) return this.refuse('usage_invalid');
    return { value: JSON.stringify(line.message), usage };
  }

  private sealedFailure(line: BatchResultLine): { value: string } | undefined {
    const type = line.outcome === 'errored' ? line.errorType : line.outcome;
    this.deps.logger.warn(...batchLog.resultErrored(type));
    const code = line.outcome === 'errored' ? DETERMINISTIC_FAILURES.get(type) : undefined;
    return code === undefined ? undefined : { value: failureMarker(code) };
  }

  private refuse(reason: BatchResultRefusal): undefined {
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
    return { sealedIds: [], usage: [] };
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
    const known = this.knownByOrg.get(orgId);
    if (known !== undefined) return known;
    const listed = await this.deps.manifests(orgId).listOpen();
    const withBatch = listed.filter((manifest) => manifest.open !== undefined);
    const retiring = withBatch.filter((manifest) => manifest.open?.cancelRequested === true);
    const found = {
      open: new Set(withBatch.map((manifest) => manifest.wikiRequestId)),
      retiring: new Set(retiring.map((manifest) => manifest.wikiRequestId)),
      orphans: new Map<string, BatchManifest>(),
    };
    this.knownByOrg.set(orgId, found);
    return found;
  }

  private forget(orgId: string, wikiRequestId: string): void {
    const known = this.knownByOrg.get(orgId);
    known?.open.delete(wikiRequestId);
    known?.retiring.delete(wikiRequestId);
  }

  private now(): number {
    return this.deps.now?.() ?? Date.now();
  }
}
