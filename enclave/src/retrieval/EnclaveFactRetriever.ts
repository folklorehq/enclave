import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import {
  assertResolvedLensFor,
  type AudienceAccess,
  type FactExcerptParams,
  type FactExcerptReader,
  type FactMetadata,
  type FactRetriever,
  type FactSearchParams,
  type FactSnippetParams,
  type LensSearchParams,
  type RetrievedFact,
  type RetrieverDeps,
} from '@folklore/api';
import {
  FACT_EXCERPT_BATCH_MAX,
  FACT_EXCERPT_MAX_CHARS,
  SNIPPET_MAX_CHARS,
} from '@folklore/contracts';
import { InternalError, isAppError } from '@folklore/errors';
import { isSensitivityWithin } from '@folklore/wiki';
import { feedLineOf } from './feed-line.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { embedText } from '../inference/phala.js';
import type { TenantContext } from '../tenant/tenant-context.js';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';
import { KeyedSemaphore } from './KeyedSemaphore.js';

const LENS_SEARCH_MAX_CONCURRENCY = 4;
const LENS_FAILURE_MESSAGE = 'lens retrieval failed';

const FACT_EXCERPT_BATCH_TOO_LARGE = 'fact_excerpt_batch_too_large';

export interface FactRetrieverDeps extends RetrieverDeps {
  resolveTenant: ResolveTenant;
  s3: S3Client;
  processedBucket: string;
  processedBucketFor?: (orgId: string) => string;
  embedQuery?: (orgId: string, query: string) => Promise<number[]>;
}

/** An audience-visible hit with its decrypted body, for callers (e.g. answer synthesis) that need more than a snippet. */
export interface GatedFact {
  meta: FactMetadata;
  distance: number;
  body: string;
}

export interface LensRetrieval {
  facts: GatedFact[];
  matchedOutsideLens: boolean;
}

// semantic retrieval that never leaves the enclave. The query is
// embedded and matched against the in-enclave index; matches are audience-gated
// on content-free metadata before any body is decrypted, and a body is decrypted
// (AAD-bound to its row) only to preview a fact the caller is allowed to see.
export class EnclaveFactRetriever implements FactRetriever, FactExcerptReader {
  private readonly lensSlots = new KeyedSemaphore(LENS_SEARCH_MAX_CONCURRENCY);

  constructor(private readonly deps: FactRetrieverDeps) {}

  async search(params: FactSearchParams): Promise<RetrievedFact[]> {
    const gated = await this.retrieveGated(params, SNIPPET_MAX_CHARS);
    return gated.map((g) => ({
      id: g.meta.id,
      kind: g.meta.kind,
      occurredAt: g.meta.occurredAt,
      sourceId: g.meta.sourceId,
      sourceKind: g.meta.sourceKind,
      distance: g.distance,
      snippet: g.body,
    }));
  }

  // By-factId, no embedding, no ANN — the review queue already names its rows. Same fail-closed
  // order as search: tenant first, audience gate before any decrypt; unauthorized facts are absent.
  async snippetForFactIds(params: FactSnippetParams): Promise<Map<string, string>> {
    const { orgId, userId, factIds } = params;
    if (factIds.length === 0) return new Map();

    const tenant = this.deps.resolveTenant(orgId);
    const [metaRows, access] = await Promise.all([
      this.deps.loadFactMetadata(orgId, factIds),
      this.deps.resolveAudienceAccess(orgId, userId),
    ]);
    return this.decryptVisible(tenant.crypto, orgId, metaRows, access, SNIPPET_MAX_CHARS);
  }

  // Access is resolved fresh, never from the cache, and the batch is bounded.
  async excerptsForFactIds(params: FactExcerptParams): Promise<Map<string, string>> {
    const { orgId, userId, factIds } = params;
    if (factIds.length === 0) return new Map();
    if (factIds.length > FACT_EXCERPT_BATCH_MAX) throw new Error(FACT_EXCERPT_BATCH_TOO_LARGE);
    const limit = this.clampExcerptChars(params.maxChars);
    if (limit === 0) return new Map();
    const resolveFreshAccess = this.deps.resolveFreshAudienceAccess;
    if (!resolveFreshAccess) return new Map();

    const tenant = this.deps.resolveTenant(orgId);
    const [metaRows, access] = await Promise.all([
      this.deps.loadFactMetadata(orgId, factIds),
      resolveFreshAccess(orgId, userId),
    ]);
    return this.decryptVisible(tenant.crypto, orgId, metaRows, access, limit);
  }

  // The page feed: the same fresh access gate and batch bound as the excerpts, then one extractive line per visible fact.
  async feedLinesForFactIds(params: FactSnippetParams): Promise<Map<string, string>> {
    const { orgId, userId, factIds } = params;
    if (factIds.length === 0) return new Map();
    if (factIds.length > FACT_EXCERPT_BATCH_MAX) throw new Error(FACT_EXCERPT_BATCH_TOO_LARGE);
    const resolveFreshAccess = this.deps.resolveFreshAudienceAccess;
    if (!resolveFreshAccess) return new Map();

    const tenant = this.deps.resolveTenant(orgId);
    const [metaRows, access] = await Promise.all([
      this.deps.loadFactMetadata(orgId, factIds),
      resolveFreshAccess(orgId, userId),
    ]);
    const visible = metaRows.filter((meta) => this.isVisible(meta, access));
    const lines = await Promise.all(
      visible.map(async (meta) => ({
        id: meta.id,
        line: feedLineOf(await this.decryptRecord(tenant.crypto, orgId, meta)),
      })),
    );
    return new Map(lines.flatMap(({ id, line }) => (line === null ? [] : [[id, line] as const])));
  }

  // Embed → ANN → audience-gate → decrypt, shared by snippet search and answer grounding.
  // bodyLimit caps decrypted body length; nothing above the caller's audience is ever decrypted.
  async retrieveGated(params: FactSearchParams, bodyLimit: number): Promise<GatedFact[]> {
    return this.retrieveGatedWith(params, bodyLimit, () =>
      this.deps.resolveAudienceAccess(params.orgId, params.userId),
    );
  }

  async retrieveGatedForAccess(
    params: FactSearchParams,
    access: AudienceAccess,
    bodyLimit: number,
  ): Promise<GatedFact[]> {
    return this.retrieveGatedWith(params, bodyLimit, async () => access);
  }

  private async retrieveGatedWith(
    params: FactSearchParams,
    bodyLimit: number,
    accessFor: () => Promise<AudienceAccess>,
  ): Promise<GatedFact[]> {
    const { orgId, query, limit } = params;
    if (!query.trim() || limit <= 0) return [];

    // Fail closed BEFORE any index/keyring is touched: an orgId not in the assigned set throws here
    // (§4.2). The tenant's own HNSW self-guards on orgId too, so retrieval only ever answers for it.
    const tenant = this.deps.resolveTenant(orgId);

    const queryVec = await this.embed(orgId, query);
    await tenant.hnsw.whenReady();
    const hits = tenant.hnsw.query(orgId, queryVec, limit);
    return this.gateAndDecrypt(tenant, params, hits, bodyLimit, accessFor);
  }

  // Ranks only the facts the caller's lens allows; the per-fact audience gate still runs on every hit.
  async retrieveInLens(params: LensSearchParams, bodyLimit: number): Promise<LensRetrieval> {
    const { orgId, userId, query, limit } = params;
    if (!query.trim() || limit <= 0) return { facts: [], matchedOutsideLens: false };

    const tenant = this.deps.resolveTenant(orgId);
    assertResolvedLensFor(params.lens, { orgId, userId }, params.lens.audienceId);
    try {
      return await this.searchLens(tenant, params, bodyLimit);
    } catch (err) {
      // The lens holds up to ~200k fact ids; a raw error from a callee must not carry them into a log.
      if (isAppError(err)) throw err;
      throw new InternalError(LENS_FAILURE_MESSAGE);
    }
  }

  private async searchLens(
    tenant: TenantContext,
    params: LensSearchParams,
    bodyLimit: number,
  ): Promise<LensRetrieval> {
    const { orgId, query, limit, lens } = params;
    if (lens.factIds.size === 0) {
      return { facts: [], matchedOutsideLens: await lens.hasVisibleFactOutside() };
    }

    const queryVec = await this.embed(orgId, query);
    await tenant.hnsw.whenReady();
    const facts = await this.lensSlots.run(orgId, async () => {
      const hits = tenant.hnsw
        .query(orgId, queryVec, limit, lens.factIds)
        .filter((hit) => lens.factIds.has(hit.factId));
      return this.gateAndDecrypt(tenant, params, hits, bodyLimit, () =>
        this.deps.resolveAudienceAccess(orgId, params.userId),
      );
    });
    if (facts.length > 0) return { facts, matchedOutsideLens: false };
    return { facts: [], matchedOutsideLens: await lens.hasVisibleFactOutside() };
  }

  private embed(orgId: string, query: string): Promise<number[]> {
    return this.deps.embedQuery ? this.deps.embedQuery(orgId, query) : embedText(query);
  }

  private async gateAndDecrypt(
    tenant: TenantContext,
    params: FactSearchParams,
    hits: { factId: string; distance: number }[],
    bodyLimit: number,
    accessFor: () => Promise<AudienceAccess>,
  ): Promise<GatedFact[]> {
    if (hits.length === 0) return [];
    const { orgId } = params;

    const [metaRows, access] = await Promise.all([
      this.deps.loadFactMetadata(
        orgId,
        hits.map((h) => h.factId),
      ),
      accessFor(),
    ]);
    const metaById = new Map(metaRows.map((m) => [m.id, m]));

    const results: GatedFact[] = [];
    for (const hit of hits) {
      const meta = metaById.get(hit.factId);
      if (!meta) continue;
      if (!this.isVisible(meta, access)) continue;
      const body = await this.decryptBody(tenant.crypto, orgId, meta, bodyLimit);
      if (body === null) continue;
      results.push({ meta, distance: hit.distance, body });
    }
    return results;
  }

  // Independent, fail-closed work (decryptBody returns null on failure), so the per-fact decrypts
  // run concurrently instead of N serial S3 GET + decrypt round-trips for an N-row page.
  private async decryptVisible(
    crypto: EnclaveCrypto,
    orgId: string,
    metaRows: FactMetadata[],
    access: AudienceAccess,
    bodyLimit: number,
  ): Promise<Map<string, string>> {
    const visible = metaRows.filter((meta) => this.isVisible(meta, access));
    const decrypted = await Promise.all(
      visible.map(async (meta) => ({
        meta,
        body: await this.decryptBody(crypto, orgId, meta, bodyLimit),
      })),
    );

    const bodies = new Map<string, string>();
    for (const { meta, body } of decrypted) {
      // decryptBody returns '' for a null bodyS3Key, so an empty body means absent.
      if (body === null || body === '') continue;
      bodies.set(meta.id, body);
    }
    return bodies;
  }

  private clampExcerptChars(maxChars: number): number {
    if (Number.isNaN(maxChars)) return 0;
    return Math.max(0, Math.min(Math.trunc(maxChars), FACT_EXCERPT_MAX_CHARS));
  }

  private isVisible(meta: FactMetadata, access: AudienceAccess): boolean {
    // sensitivity ceiling applies regardless of source-kind grant ('*' included).
    if (!isSensitivityWithin(meta.sensitivityLevel, access.maxSensitivity)) return false;
    if (access.allowedSourceKinds === '*') return true;
    return access.allowedSourceKinds.has(meta.sourceKind);
  }

  private async decryptBody(
    crypto: EnclaveCrypto,
    orgId: string,
    meta: FactMetadata,
    bodyLimit: number,
  ): Promise<string | null> {
    if (!meta.bodyS3Key) return '';
    const fact = await this.decryptRecord(crypto, orgId, meta);
    if (fact === null) return null;
    const content = fact['content'] as Record<string, unknown> | undefined;
    const body = (content?.['body'] as string | undefined) ?? '';
    return body.slice(0, bodyLimit);
  }

  // The sealed record, opened under the fact's own context; any failure (or an owner-bound envelope) yields null.
  private async decryptRecord(
    crypto: EnclaveCrypto,
    orgId: string,
    meta: FactMetadata,
  ): Promise<Record<string, unknown> | null> {
    if (!meta.bodyS3Key) return null;
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({
          Bucket: this.deps.processedBucketFor?.(orgId) ?? this.deps.processedBucket,
          Key: meta.bodyS3Key,
        }),
      );
      const raw = await obj.Body!.transformToByteArray();
      const enc = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      const plaintext = await crypto.decryptFactBody(enc, { factId: meta.id, orgId });
      return JSON.parse(plaintext.toString('utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
}
