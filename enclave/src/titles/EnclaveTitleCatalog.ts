import { SEALED_TITLE_KINDS, sealedTitleKey, type SealedTitleKind } from '@folklore/contracts';
import type {
  CommittedSealedTitle,
  NewSealedTitle,
  SealedTitleRepositoryPort,
  SealedTitleRow,
  TitleCatalogPort,
  TitleRef,
} from '@folklore/api';
import { mapWithConcurrency } from '@folklore/utils';
import { EncryptionContextMismatchError } from '../crypto/esdk.js';
import type { IndexResidencyManager } from '../hnsw/IndexResidencyManager.js';
import { errorCode as errorCodeOf, errorType } from '../logging/error-fields.js';
import { TenantKeyedHasher } from '../sealing/TenantKeyedHasher.js';
import { TenantContextZeroizedError, type TenantContext } from '../tenant/tenant-context.js';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';
import { TitleIndex, type TitleEntry } from './TitleIndex.js';
import { padTitle, sealedTitleMac, unpadTitle } from './title-padding.js';

export type TitleCatalogEvent =
  | 'title_index_loaded'
  | 'title_index_refreshed'
  | 'title_index_reloaded_on_count_mismatch'
  | 'title_unseal_failed'
  | 'title_index_load_failed';

export interface TitleCatalogLogFields {
  kind?: SealedTitleKind | 'unknown';
  rows?: number;
  ms?: number;
  errorCode?: string;
}

// Slots sized so every resident 10,000-title tenant fits in about 1% of the smallest enclave memory tier.
export const TITLE_INDEX_RESIDENCY = 23;

interface ReloadShape {
  rowCount: number;
  total: number;
}

interface ReloadBackoff {
  windowMs: number;
  replaced?: ReloadShape;
}

export interface EnclaveTitleCatalogDeps {
  resolveTenant: ResolveTenant;
  rows: SealedTitleRepositoryPort;
  residency: IndexResidencyManager<TitleIndex>;
  now?: () => number;
  log?: (event: TitleCatalogEvent, fields: TitleCatalogLogFields) => void;
}

interface Unsealed {
  entries: TitleEntry[];
  skippedSeqs: string[];
  unseenSeqs: string[];
}

const SKIPPED = 'skipped';
const UNSEEN = 'unseen';
type Opened = TitleEntry | typeof SKIPPED | typeof UNSEEN;

const FRESHNESS_MS = 5_000;
const RELOAD_MIN_INTERVAL_MS = 60_000;
const RELOAD_MAX_INTERVAL_MS = 15 * 60_000;
const LOAD_BACKOFF_MS = 30_000;
const LOAD_BACKOFF_CODE = 'title_index_load_backoff';
const TITLE_UNSEAL_CONCURRENCY = 8;
const ALL_ROWS_AFTER = '0';
const ORG_MISMATCH_CODE = 'org_mismatch';
const CONTEXT_MISMATCH_CODE = 'context_mismatch';
const ESDK_MALFORMED_CODE = 'esdk_malformed';
const REPEATING_MESSAGE_CODES: ReadonlySet<string> = new Set([
  'sealed_title_malformed',
  'sealed_title_ref_invalid',
]);
const ESDK_MALFORMED_MESSAGE =
  /^(Not a supported message format version|Incomplete Header|Invalid Signature|Malformed)/;

export class EnclaveTitleCatalog implements TitleCatalogPort {
  private readonly resolveTenant: ResolveTenant;
  private readonly rows: SealedTitleRepositoryPort;
  private readonly residency: IndexResidencyManager<TitleIndex>;
  private readonly now: () => number;
  private readonly log: (event: TitleCatalogEvent, fields: TitleCatalogLogFields) => void;
  private readonly installed = new Map<string, TitleIndex>();
  private readonly notes = new Map<string, TitleEntry[]>();
  private readonly reloadCarry = new Map<string, number>();
  private readonly backoff = new Map<string, ReloadBackoff>();
  private readonly loadFailedAt = new Map<string, number>();
  private readonly retired = new WeakSet<TitleIndex>();
  private readonly catchUps = new Map<string, Promise<void>>();

  constructor(deps: EnclaveTitleCatalogDeps) {
    this.resolveTenant = deps.resolveTenant;
    this.rows = deps.rows;
    this.residency = deps.residency;
    this.now = deps.now ?? Date.now;
    this.log = deps.log ?? (() => {});
  }

  async resolve(orgId: string, refs: readonly TitleRef[]): Promise<ReadonlyMap<string, string>> {
    const found = await this.read(orgId, (index) => {
      const titles = new Map<string, string>();
      for (const ref of refs) {
        const key = sealedTitleKey(ref.kind, ref.subjectId);
        const title = index.get(key);
        if (title !== undefined) titles.set(key, title);
      }
      return titles;
    });
    return found ?? new Map();
  }

  async sealedSubjects(orgId: string, kind: SealedTitleKind): Promise<string[]> {
    return (await this.read(orgId, (index) => index.subjects(kind))) ?? [];
  }

  async seal(
    orgId: string,
    ref: TitleRef & { rowId: string },
    title: string,
  ): Promise<NewSealedTitle> {
    const tenant = this.resolveTenant(orgId);
    const hasher = this.macHasher(tenant);
    const binding = { ...ref, orgId };
    let padded: Buffer | undefined;
    try {
      padded = padTitle(title, sealedTitleMac(hasher, binding));
      const sealed = await tenant.crypto.encryptSealedTitle(padded, binding);
      return { id: ref.rowId, kind: ref.kind, subjectId: ref.subjectId, sealed };
    } finally {
      padded?.fill(0);
      hasher.zeroize();
    }
  }

  noteCommitted(orgId: string, row: CommittedSealedTitle, title: string): void {
    const entry = { key: sealedTitleKey(row.kind, row.subjectId), seq: row.seq, title };
    const installed = this.installed.get(orgId);
    if (installed) installed.noteCommitted(entry);
    else this.notes.get(orgId)?.push(entry);
  }

  // Concurrent misses share one read; it fetches only rows above the watermark, so it decrypts nothing a refresh would not, and a load in backoff stays refused.
  catchUp(orgId: string): Promise<void> {
    const inFlight = this.catchUps.get(orgId);
    if (inFlight) return inFlight;
    const run = this.refreshNow(orgId).finally(() => this.catchUps.delete(orgId));
    this.catchUps.set(orgId, run);
    return run;
  }

  // The residency evict defers disposing a pinned index, so the catalog drops its own state for the org at once.
  forgetTenant(orgId: string): void {
    this.installed.delete(orgId);
    this.notes.delete(orgId);
    this.reloadCarry.delete(orgId);
    this.backoff.delete(orgId);
    this.loadFailedAt.delete(orgId);
  }

  private async refreshNow(orgId: string): Promise<void> {
    try {
      await this.residency.withIndex(
        orgId,
        () => this.loadAll(orgId),
        async (index) => {
          this.install(orgId, index);
          await this.refresh(orgId, index, true);
        },
      );
    } catch (error) {
      if (errorCodeOf(error) !== LOAD_BACKOFF_CODE) this.logLoadFailure(error);
    }
  }

  private async read<R>(orgId: string, use: (index: TitleIndex) => R): Promise<R | undefined> {
    try {
      return await this.readWithReload(orgId, use, true);
    } catch (error) {
      if (errorCodeOf(error) !== LOAD_BACKOFF_CODE) this.logLoadFailure(error);
      return undefined;
    }
  }

  private async readWithReload<R>(
    orgId: string,
    use: (index: TitleIndex) => R,
    mayReload: boolean,
  ): Promise<R | undefined> {
    const outcome = await this.residency.withIndex(
      orgId,
      () => this.loadAll(orgId),
      async (index): Promise<{ value: R } | null> => {
        this.install(orgId, index);
        const stale = await this.refresh(orgId, index);
        if (!stale || !mayReload) return { value: use(index) };
        this.beginReload(orgId, index);
        return null;
      },
    );
    return outcome ? outcome.value : this.readWithReload(orgId, use, false);
  }

  private async loadAll(orgId: string): Promise<TitleIndex> {
    this.refuseDuringBackoff(orgId);
    const started = this.now();
    this.notes.set(orgId, this.notes.get(orgId) ?? []);
    try {
      const { rows, total } = await this.rows.rowsAfter(orgId, ALL_ROWS_AFTER);
      const index: TitleIndex = TitleIndex.empty(() => this.forget(orgId, index));
      const unsealed = await this.unsealAll(orgId, rows);
      index.apply(unsealed.entries, unsealed.skippedSeqs, unsealed.unseenSeqs);
      index.checkedAt = this.now();
      index.reloadedAt = this.reloadCarry.get(orgId) ?? this.reloadFloor(orgId);
      this.reloadCarry.delete(orgId);
      this.adjustBackoff(orgId, { rowCount: index.rowCount, total });
      this.loadFailedAt.delete(orgId);
      this.log('title_index_loaded', { rows: rows.length, ms: this.now() - started });
      return index;
    } catch (error) {
      this.notes.delete(orgId);
      this.loadFailedAt.set(orgId, this.now());
      throw error;
    }
  }

  // After an eviction a back-off entry still stands, so the fresh index must not reload at once.
  private reloadFloor(orgId: string): number {
    return this.backoff.has(orgId) ? this.now() : Number.NEGATIVE_INFINITY;
  }

  private refuseDuringBackoff(orgId: string): void {
    const failedAt = this.loadFailedAt.get(orgId);
    if (failedAt === undefined || this.now() - failedAt >= LOAD_BACKOFF_MS) return;
    this.notes.delete(orgId);
    throw Object.assign(new Error(LOAD_BACKOFF_CODE), { code: LOAD_BACKOFF_CODE });
  }

  private install(orgId: string, index: TitleIndex): void {
    if (this.retired.has(index) || this.installed.get(orgId) === index) return;
    this.installed.set(orgId, index);
    for (const entry of this.notes.get(orgId) ?? []) index.noteCommitted(entry);
    this.notes.delete(orgId);
  }

  private beginReload(orgId: string, index: TitleIndex): void {
    this.retired.add(index);
    if (this.installed.get(orgId) === index) this.installed.delete(orgId);
    this.notes.set(orgId, this.notes.get(orgId) ?? []);
    this.residency.discard(orgId, index);
  }

  // A retired index is replaced by a reload that still needs the buffered notes and the carried window.
  private forget(orgId: string, index: TitleIndex): void {
    if (this.retired.has(index)) return;
    const installed = this.installed.get(orgId);
    if (installed !== undefined && installed !== index) return;
    this.installed.delete(orgId);
    this.notes.delete(orgId);
    this.reloadCarry.delete(orgId);
    this.loadFailedAt.delete(orgId);
  }

  // A forced refresh skips the freshness window, takes no reload slot and leaves checkedAt alone, so frequent catch-ups cannot starve the count-check reload that recovers unseen rows.
  private async refresh(orgId: string, index: TitleIndex, force = false): Promise<boolean> {
    const started = this.now();
    if (!force && started - index.checkedAt < FRESHNESS_MS) return false;
    if (!force) index.checkedAt = started;
    try {
      const { rows, total } = await this.rows.rowsAfter(orgId, index.watermark);
      const unsealed = await this.unsealAll(orgId, rows);
      index.apply(unsealed.entries, unsealed.skippedSeqs, unsealed.unseenSeqs);
      if (rows.length > 0) {
        this.log('title_index_refreshed', { rows: rows.length, ms: this.now() - started });
      }
      return !force && index.rowCount !== total && this.takeReloadSlot(orgId, index, total);
    } catch (error) {
      this.logLoadFailure(error);
      return false;
    }
  }

  private takeReloadSlot(orgId: string, index: TitleIndex, total: number): boolean {
    const at = this.now();
    const windowMs = this.backoff.get(orgId)?.windowMs ?? RELOAD_MIN_INTERVAL_MS;
    if (at - index.reloadedAt < windowMs) return false;
    index.reloadedAt = at;
    this.reloadCarry.set(orgId, at);
    this.backoff.set(orgId, { windowMs, replaced: { rowCount: index.rowCount, total } });
    this.log('title_index_reloaded_on_count_mismatch', { rows: total });
    return true;
  }

  // A reload that ends where the one it replaced did is stuck on a row that never opens, so the next one waits longer.
  private adjustBackoff(orgId: string, loaded: ReloadShape): void {
    const state = this.backoff.get(orgId);
    if (!state?.replaced) return;
    const stuck =
      state.replaced.rowCount === loaded.rowCount && state.replaced.total === loaded.total;
    const windowMs = stuck
      ? Math.min(state.windowMs * 2, RELOAD_MAX_INTERVAL_MS)
      : RELOAD_MIN_INTERVAL_MS;
    this.backoff.set(orgId, { windowMs });
  }

  private async unsealAll(orgId: string, rows: readonly SealedTitleRow[]): Promise<Unsealed> {
    const tenant = this.resolveTenant(orgId);
    const hasher = this.macHasher(tenant);
    try {
      const opened = await mapWithConcurrency(rows, TITLE_UNSEAL_CONCURRENCY, (row) =>
        this.unseal(tenant, hasher, orgId, row),
      );
      const entries = opened.filter((result): result is TitleEntry => typeof result === 'object');
      const skippedSeqs = rows.filter((_row, i) => opened[i] === SKIPPED).map((row) => row.seq);
      const unseenSeqs = rows.filter((_row, i) => opened[i] === UNSEEN).map((row) => row.seq);
      return { entries, skippedSeqs, unseenSeqs };
    } finally {
      hasher.zeroize();
    }
  }

  private async unseal(
    tenant: TenantContext,
    hasher: TenantKeyedHasher,
    orgId: string,
    row: SealedTitleRow,
  ): Promise<Opened> {
    if (row.orgId !== orgId) return this.skipped(row, ORG_MISMATCH_CODE);
    const binding = { orgId, kind: row.kind, subjectId: row.subjectId, rowId: row.id };
    try {
      const padded = await tenant.crypto.decryptSealedTitle(row.sealed, binding);
      const title = unpadTitle(padded, sealedTitleMac(hasher, binding));
      return { key: sealedTitleKey(row.kind, row.subjectId), seq: row.seq, title };
    } catch (error) {
      const code = this.repeatingFailureCode(error);
      if (code !== null) return this.skipped(row, code);
      // Unidentified: the row stays unseen, so the count check retries it instead of a bad row failing the load.
      this.logUnseal(row, errorCodeOf(error) ?? errorType(error));
      return UNSEEN;
    }
  }

  private repeatingFailureCode(error: unknown): string | null {
    if (error instanceof EncryptionContextMismatchError) return CONTEXT_MISMATCH_CODE;
    if (!(error instanceof Error)) return null;
    if (REPEATING_MESSAGE_CODES.has(error.message)) return error.message;
    return ESDK_MALFORMED_MESSAGE.test(error.message) ? ESDK_MALFORMED_CODE : null;
  }

  private skipped(row: SealedTitleRow, errorCode: string): typeof SKIPPED {
    this.logUnseal(row, errorCode);
    return SKIPPED;
  }

  private logUnseal(row: SealedTitleRow, errorCode: string): void {
    const kind = SEALED_TITLE_KINDS.includes(row.kind) ? row.kind : 'unknown';
    this.log('title_unseal_failed', { kind, errorCode });
  }

  private logLoadFailure(error: unknown): void {
    this.log('title_index_load_failed', { errorCode: errorCodeOf(error) ?? errorType(error) });
  }

  private macHasher(tenant: TenantContext): TenantKeyedHasher {
    const key = tenant.titleMacKey();
    if (!key) throw new TenantContextZeroizedError(tenant.tenantId);
    return new TenantKeyedHasher(key, () => new TenantContextZeroizedError(tenant.tenantId));
  }
}
