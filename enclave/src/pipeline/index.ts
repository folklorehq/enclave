import { randomUUID, createHash } from 'node:crypto';
import { buildClient, CommitmentPolicy } from '@aws-crypto/client-node';
import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { embedText } from '../inference/phala.js';
import { normalizeWebhookEvent } from '@folklore/connectors';
import type { HnswStore } from '../hnsw/index.js';
import type { KmsKeyringNode } from '@aws-crypto/client-node';

const { encrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

export interface ProcessedFact {
  factId: string;
  orgId: string;
  sourceKind: string;
  sourceFactId: string;
  occurredAt: string; // ISO8601
  bodyS3Key: string;
  bodyHash: string;
  kind: 'content' | 'transition';
  containerRefs: string[];
  explicitLinks: string[];
  sourceThreadId?: string;
  /** Container seeds for containers the fact belongs to; worker upserts these. */
  containerSeeds: { sourceContainerId: string; label: string; shape: string }[];
  /** Top-K nearest neighbors from the HNSW index, searched before this fact
   *  was inserted. Used by the worker for semantic similarity scoring (ADL #34). */
  hnswNeighbors: { factId: string; similarity: number }[];
}

const KNOWN_SOURCES = new Set(['github', 'slack', 'linear', 'notion', 'intercom', 'meeting']);

export class Pipeline {
  constructor(
    private readonly hnsw: HnswStore,
    private readonly s3: S3Client,
    private readonly keyring: KmsKeyringNode,
    private readonly processedBucket: string,
    private readonly orgId: string,
  ) {}

  async handle(plaintext: Buffer, source: string, eventType: string): Promise<ProcessedFact[]> {
    if (!KNOWN_SOURCES.has(source)) {
      console.warn('unknown source kind — dropping', { source });
      return [];
    }

    let payload: unknown;
    try {
      payload = JSON.parse(plaintext.toString('utf8'));
    } catch {
      console.warn('failed to parse event body — dropping', { source });
      return [];
    }

    const { facts: normalizedFacts, containers } = normalizeWebhookEvent(
      source,
      eventType,
      payload,
    );
    if (normalizedFacts.length === 0) {
      return [];
    }

    const containerByRef = new Map(containers.map((c) => [c.sourceContainerId, c]));

    const results: ProcessedFact[] = [];

    for (const fact of normalizedFacts) {
      const factId = randomUUID();
      const embedStr =
        fact.content?.body ?? fact.transition?.transitionType ?? JSON.stringify(fact.raw);

      const bodyStr = JSON.stringify(fact);
      const bodyBytes = Buffer.from(bodyStr, 'utf8');
      const bodyHash = createHash('sha256').update(bodyBytes).digest('hex');

      const { result } = await encrypt(this.keyring, bodyBytes, {
        encryptionContext: { factId, orgId: this.orgId, purpose: 'fact-body', sha256: bodyHash },
      });
      const bodyS3Key = `facts/${this.orgId}/${factId}`;
      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.processedBucket,
          Key: bodyS3Key,
          Body: result.toString('base64'),
          ContentType: 'text/plain',
          Metadata: { 'body-sha256': bodyHash },
        }),
      );

      const embedding = await embedText(embedStr);
      // Search BEFORE inserting so the new fact doesn't appear as its own neighbor.
      const hnswNeighbors = this.hnsw
        .search(embedding, 20)
        .map((n) => ({ factId: n.factId, similarity: Math.max(0, 1 - n.distance) }))
        .filter((n) => n.similarity >= 0.2);
      this.hnsw.insert(factId, embedding);

      results.push({
        factId,
        orgId: this.orgId,
        sourceKind: source,
        sourceFactId: fact.sourceFactId,
        occurredAt: fact.occurredAt.toISOString(),
        bodyS3Key,
        bodyHash,
        kind: fact.kind,
        containerRefs: fact.containerRefs,
        explicitLinks: fact.content?.explicitLinks ?? [],
        sourceThreadId: fact.sourceThreadId,
        containerSeeds: fact.containerRefs
          .map((ref) => containerByRef.get(ref))
          .filter((c): c is NonNullable<typeof c> => c != null)
          .map((c) => ({ sourceContainerId: c.sourceContainerId, label: c.label, shape: c.shape })),
        hnswNeighbors,
      });
    }

    await this.hnsw.maybeSave(this.s3, this.keyring, this.processedBucket, this.orgId);

    return results;
  }
}
