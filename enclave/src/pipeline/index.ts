import { randomUUID, createHash } from 'node:crypto';
import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { embedText } from '../inference/phala.js';
import {
  normalizeWebhookEvent,
  type NormalizedFact,
  type NormalizedContainer,
} from '@folklore/connectors';
import { EnclaveCrypto } from '../crypto/esdk.js';
import type { HnswStore } from '../hnsw/index.js';
import type { KmsKeyringNode } from '@aws-crypto/client-node';

const FILE_PATH_RE = /(?:^|[\s(,])([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_./-]+\.[a-z]{1,6})\b/g;
const ISSUE_REF_RE = /(?:^|\s)(#\d{1,6})\b/g;
const JIRA_KEY_RE = /\b([A-Z]{2,10}-\d{1,6})\b/g;
const BACKTICK_RE = /`([^`\n]{2,60})`/g;
const PR_REF_RE = /\bpr\s*#?(\d{1,6})\b/gi;
const MENTION_RE = /@([\w-]{2,39})\b/g;
const REPO_RE = /\b([\w.-]{1,39})\/([\w.-]{1,100})\b/g;
const MAX_ENTITIES = 100;

function extractEntities(text: string): string[] {
  const set = new Set<string>();
  for (const m of text.matchAll(FILE_PATH_RE)) if (m[1]) set.add(m[1].toLowerCase());
  for (const m of text.matchAll(ISSUE_REF_RE)) if (m[1]) set.add(m[1]);
  for (const m of text.matchAll(JIRA_KEY_RE)) if (m[1]) set.add(m[1]);
  for (const m of text.matchAll(BACKTICK_RE)) if (m[1]) set.add(m[1]);
  for (const m of text.matchAll(PR_REF_RE)) if (m[1]) set.add(`PR#${m[1]}`);
  for (const m of text.matchAll(MENTION_RE)) if (m[1]) set.add(`@${m[1]}`);
  for (const m of text.matchAll(REPO_RE)) {
    const full = (m[0] ?? '').trim();
    if (!full.includes('.')) set.add(full.toLowerCase());
  }
  return [...set]
    .map((e) => {
      if (/^#\d+$/.test(e)) return `issue:${e.slice(1)}`;
      const jira = /^[A-Z]{2,10}-(\d+)$/.exec(e);
      return jira ? `issue:${jira[1]!}` : e;
    })
    .slice(0, MAX_ENTITIES);
}

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
  /** Entities extracted from the fact body before encryption; stored in DB for
   *  association scoring so the worker never needs to decrypt (ADL #12). */
  extractedEntities: string[];
  /** Container seeds for containers the fact belongs to; worker upserts these. */
  containerSeeds: { sourceContainerId: string; label: string; shape: string }[];
  /** Top-K nearest neighbors from the HNSW index, searched before this fact
   *  was inserted. Used by the worker for semantic similarity scoring (ADL #34). */
  hnswNeighbors: { factId: string; similarity: number }[];
}

const KNOWN_SOURCES = new Set(['github', 'slack', 'linear', 'notion', 'intercom', 'meeting']);

export class Pipeline {
  private readonly crypto: EnclaveCrypto;

  constructor(
    private readonly hnsw: HnswStore,
    private readonly s3: S3Client,
    private readonly keyring: KmsKeyringNode,
    private readonly processedBucket: string,
    private readonly orgId: string,
  ) {
    this.crypto = new EnclaveCrypto(keyring);
  }

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

    return this.processFacts(normalizedFacts, containers, source);
  }

  async handleNormalized(plaintext: Buffer, sourceKind: string): Promise<ProcessedFact[]> {
    let parsed: { facts: NormalizedFact[]; containers: NormalizedContainer[] };
    try {
      parsed = JSON.parse(plaintext.toString('utf8')) as typeof parsed;
    } catch {
      console.warn('pull-normalized: failed to parse payload — dropping');
      return [];
    }

    const facts = parsed.facts.map((f) => ({
      ...f,
      occurredAt: new Date(f.occurredAt as unknown as string),
    }));

    if (facts.length === 0) return [];

    return this.processFacts(facts, parsed.containers, sourceKind);
  }

  private async processFacts(
    normalizedFacts: NormalizedFact[],
    containers: NormalizedContainer[],
    source: string,
  ): Promise<ProcessedFact[]> {
    const containerByRef = new Map(containers.map((c) => [c.sourceContainerId, c]));
    const results: ProcessedFact[] = [];

    for (const fact of normalizedFacts) {
      const factId = randomUUID();
      const embedStr =
        fact.content?.body ?? fact.transition?.transitionType ?? JSON.stringify(fact.raw);

      const bodyStr = JSON.stringify(fact);
      const extractedEntities = extractEntities(bodyStr);
      const bodyBytes = Buffer.from(bodyStr, 'utf8');
      const bodyHash = createHash('sha256').update(bodyBytes).digest('hex');

      const encrypted = await this.crypto.encryptFactBody(bodyBytes, {
        factId,
        orgId: this.orgId,
        sha256: bodyHash,
      });
      const bodyS3Key = `facts/${this.orgId}/${factId}`;
      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.processedBucket,
          Key: bodyS3Key,
          Body: encrypted.toString('base64'),
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
        extractedEntities,
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
