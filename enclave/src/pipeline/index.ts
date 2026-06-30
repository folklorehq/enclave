import { embedText } from '../inference/ollama.js';
import { PrAnalyzer, type PrFile } from './pr-analyzer.js';
import type { EnclaveFactPersister, PersistArgs } from '../db/persist.js';
import type { HnswStore } from '../hnsw/index.js';
import type { S3Client } from '@aws-sdk/client-s3';
import type { KmsKeyringNode } from '@aws-crypto/client-node';

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

export class Pipeline {
  private readonly prAnalyzer = new PrAnalyzer();

  constructor(
    private readonly persister: EnclaveFactPersister,
    private readonly hnsw: HnswStore,
    private readonly s3: S3Client,
    private readonly keyring: KmsKeyringNode,
    private readonly processedBucket: string,
    private readonly orgId: string,
  ) {}

  async handle(plaintext: Buffer, source: string): Promise<void> {
    if (!isKnownSource(source)) {
      console.warn('unknown source kind — dropping', { source });
      return;
    }

    let body: unknown;
    try {
      body = JSON.parse(plaintext.toString('utf8'));
    } catch {
      console.warn('failed to parse event body — dropping', { source });
      return;
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

    const args: PersistArgs = {
      orgId: this.orgId,
      sourceKind: source,
      sourceFactId: extractSourceFactId(body),
      occurredAt: new Date(),
      body: JSON.stringify(body),
    };

    const [embedding, factId] = await Promise.all([
      embedText(args.body),
      this.persister.persist(args),
    ]);

    this.hnsw.insert(factId, embedding);
    await this.hnsw.maybeSave(this.s3, this.keyring, this.processedBucket, this.orgId);
  }
}
