import { randomUUID, createHash } from 'node:crypto';
import { buildClient, CommitmentPolicy } from '@aws-crypto/client-node';
import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { embedText } from '../inference/phala.js';
import { PrAnalyzer, type PrFile } from './pr-analyzer.js';
import type { HnswStore } from '../hnsw/index.js';
import type { KmsKeyringNode } from '@aws-crypto/client-node';

const { encrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

type SourceKind = 'github' | 'slack' | 'linear' | 'notion' | 'intercom';

const KNOWN_SOURCES = new Set<SourceKind>(['github', 'slack', 'linear', 'notion', 'intercom']);

function isKnownSource(s: string): s is SourceKind {
  return KNOWN_SOURCES.has(s as SourceKind);
}

function extractSourceFactId(body: unknown): string {
  if (body !== null && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    const id = b['id'] ?? b['node_id'] ?? b['ts'] ?? b['identifier'];
    if (typeof id === 'string' || typeof id === 'number') return String(id);
  }
  return Buffer.from(JSON.stringify(body)).toString('base64url').slice(0, 64);
}

interface PullRequestPayload {
  pull_request?: {
    number?: number;
    title?: string;
    body?: string | null;
    __files?: PrFile[];
  };
}

function extractPrData(
  body: unknown,
): { title: string; prBody: string | null; files: PrFile[] } | null {
  const b = body as PullRequestPayload;
  const pr = b?.pull_request;
  if (!pr?.title) return null;
  return {
    title: pr.title,
    prBody: pr.body ?? null,
    files: Array.isArray(pr.__files) ? (pr.__files as PrFile[]) : [],
  };
}

export interface ProcessedFact {
  factId: string;
  orgId: string;
  sourceKind: string;
  sourceFactId: string;
  occurredAt: string; // ISO8601
  bodyS3Key: string;
  bodyHash: string;
}

export class Pipeline {
  private readonly prAnalyzer = new PrAnalyzer();

  constructor(
    private readonly hnsw: HnswStore,
    private readonly s3: S3Client,
    private readonly keyring: KmsKeyringNode,
    private readonly processedBucket: string,
    private readonly orgId: string,
  ) {}

  async handle(plaintext: Buffer, source: string): Promise<ProcessedFact | null> {
    if (!isKnownSource(source)) {
      console.warn('unknown source kind — dropping', { source });
      return null;
    }

    let body: unknown;
    try {
      body = JSON.parse(plaintext.toString('utf8'));
    } catch {
      console.warn('failed to parse event body — dropping', { source });
      return null;
    }

    if (source === 'github') {
      const prData = extractPrData(body);
      if (prData) {
        const analysis = await this.prAnalyzer.analyze(prData.title, prData.prBody, prData.files);
        if (analysis) {
          (body as Record<string, unknown>)['__pr_analysis'] = analysis;
        }
      }
    }

    const factId = randomUUID();
    const sourceFactId = extractSourceFactId(body);
    const bodyStr = JSON.stringify(body);
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

    const embedding = await embedText(bodyStr);
    this.hnsw.insert(factId, embedding);
    await this.hnsw.maybeSave(this.s3, this.keyring, this.processedBucket, this.orgId);

    return {
      factId,
      orgId: this.orgId,
      sourceKind: source,
      sourceFactId,
      occurredAt: new Date().toISOString(),
      bodyS3Key,
      bodyHash,
    };
  }
}
