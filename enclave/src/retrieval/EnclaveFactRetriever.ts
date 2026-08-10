import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type {
  AudienceAccess,
  FactMetadata,
  FactRetriever,
  FactSearchParams,
  FactSnippetParams,
  RetrievedFact,
  RetrieverDeps,
} from '@folklore/api';
import { SNIPPET_MAX_CHARS } from '@folklore/contracts';
import { isSensitivityWithin } from '@folklore/wiki';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { embedText } from '../inference/phala.js';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';

export interface FactRetrieverDeps extends RetrieverDeps {
  resolveTenant: ResolveTenant;
  s3: S3Client;
  processedBucket: string;
  processedBucketFor?: (orgId: string) => string;
}

/** An audience-visible hit with its decrypted body, for callers (e.g. answer synthesis) that need more than a snippet. */
export interface GatedFact {
  meta: FactMetadata;
  distance: number;
  body: string;
}

// semantic retrieval that never leaves the enclave. The query is
// embedded and matched against the in-enclave index; matches are audience-gated
// on content-free metadata before any body is decrypted, and a body is decrypted
// (AAD-bound to its row) only to preview a fact the caller is allowed to see.
export class EnclaveFactRetriever implements FactRetriever {
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

    // Independent, fail-closed work (decryptBody returns null on failure), so the per-fact decrypts
    // run concurrently instead of N serial S3 GET + decrypt round-trips for an N-row page.
    const visible = metaRows.filter((meta) => this.isVisible(meta, access));
    const decrypted = await Promise.all(
      visible.map(async (meta) => ({
        meta,
        body: await this.decryptBody(tenant.crypto, orgId, meta, SNIPPET_MAX_CHARS),
      })),
    );

    const snippets = new Map<string, string>();
    for (const { meta, body } of decrypted) {
      // decryptBody returns '' for a null bodyS3Key — a null body key means absent.
      if (body === null || body === '') continue;
      snippets.set(meta.id, body);
    }
    return snippets;
  }

  // Embed → ANN → audience-gate → decrypt, shared by snippet search and answer grounding.
  // bodyLimit caps decrypted body length; nothing above the caller's audience is ever decrypted.
  async retrieveGated(params: FactSearchParams, bodyLimit: number): Promise<GatedFact[]> {
    const { orgId, userId, query, limit } = params;
    if (!query.trim() || limit <= 0) return [];

    // Fail closed BEFORE any index/keyring is touched: an orgId not in the assigned set throws here
    // (§4.2). The tenant's own HNSW self-guards on orgId too, so retrieval only ever answers for it.
    const tenant = this.deps.resolveTenant(orgId);

    const queryVec = await embedText(query);
    const hits = tenant.hnsw.query(orgId, queryVec, limit);
    if (hits.length === 0) return [];

    const [metaRows, access] = await Promise.all([
      this.deps.loadFactMetadata(
        orgId,
        hits.map((h) => h.factId),
      ),
      this.deps.resolveAudienceAccess(orgId, userId),
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
      const fact = JSON.parse(plaintext.toString('utf8')) as Record<string, unknown>;
      const content = fact['content'] as Record<string, unknown> | undefined;
      const body = (content?.['body'] as string | undefined) ?? '';
      return body.slice(0, bodyLimit);
    } catch {
      return null;
    }
  }
}
