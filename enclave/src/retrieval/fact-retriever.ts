import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { KmsKeyringNode } from '@aws-crypto/client-node';
import type {
  AudienceAccess,
  FactMetadata,
  FactRetriever,
  FactSearchParams,
  RetrievedFact,
  RetrieverDeps,
} from '@folklore/api';
import { isSensitivityWithin } from '@folklore/wiki';
import { EnclaveCrypto } from '../crypto/esdk.js';
import { embedText } from '../inference/phala.js';
import type { HnswStore } from '../hnsw/index.js';

const SNIPPET_LIMIT = 280;

export interface FactRetrieverDeps extends RetrieverDeps {
  hnsw: HnswStore;
  s3: S3Client;
  keyring: KmsKeyringNode;
  processedBucket: string;
}

/** An audience-visible hit with its decrypted body, for callers (e.g. answer synthesis) that need more than a snippet. */
export interface GatedFact {
  meta: FactMetadata;
  distance: number;
  body: string;
}

// ADL #34/#6: semantic retrieval that never leaves the enclave. The query is
// embedded and matched against the in-enclave index; matches are audience-gated
// on content-free metadata before any body is decrypted, and a body is decrypted
// (AAD-bound to its row) only to preview a fact the caller is allowed to see.
export class EnclaveFactRetriever implements FactRetriever {
  private readonly crypto: EnclaveCrypto;

  constructor(private readonly deps: FactRetrieverDeps) {
    this.crypto = new EnclaveCrypto(deps.keyring);
  }

  async search(params: FactSearchParams): Promise<RetrievedFact[]> {
    const gated = await this.retrieveGated(params, SNIPPET_LIMIT);
    return gated.map((g) => ({
      id: g.meta.id,
      kind: g.meta.kind,
      occurredAt: g.meta.occurredAt,
      sourceId: g.meta.sourceId,
      distance: g.distance,
      snippet: g.body,
    }));
  }

  // Embed → ANN → audience-gate → decrypt, shared by snippet search and answer grounding.
  // bodyLimit caps decrypted body length; nothing above the caller's audience is ever decrypted.
  async retrieveGated(params: FactSearchParams, bodyLimit: number): Promise<GatedFact[]> {
    const { orgId, userId, query, limit } = params;
    if (!query.trim() || limit <= 0) return [];

    const queryVec = await embedText(query);
    const hits = this.deps.hnsw.query(orgId, queryVec, limit);
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
      const body = await this.decryptBody(orgId, meta, bodyLimit);
      if (body === null) continue;
      results.push({ meta, distance: hit.distance, body });
    }
    return results;
  }

  private isVisible(meta: FactMetadata, access: AudienceAccess): boolean {
    // ADL #6 — sensitivity ceiling applies regardless of source-kind grant ('*' included).
    if (!isSensitivityWithin(meta.sensitivityLevel, access.maxSensitivity)) return false;
    if (access.allowedSourceKinds === '*') return true;
    return access.allowedSourceKinds.has(meta.sourceKind);
  }

  private async decryptBody(
    orgId: string,
    meta: FactMetadata,
    bodyLimit: number,
  ): Promise<string | null> {
    if (!meta.bodyS3Key) return '';
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.processedBucket, Key: meta.bodyS3Key }),
      );
      const raw = await obj.Body!.transformToByteArray();
      const enc = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      const plaintext = await this.crypto.decryptFactBody(enc, { factId: meta.id, orgId });
      const fact = JSON.parse(plaintext.toString('utf8')) as Record<string, unknown>;
      const content = fact['content'] as Record<string, unknown> | undefined;
      const body = (content?.['body'] as string | undefined) ?? '';
      return body.slice(0, bodyLimit);
    } catch {
      return null;
    }
  }
}
