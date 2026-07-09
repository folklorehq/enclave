import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';
import { GetObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { EMBED_DIM } from '../inference/phala.js';

const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

// hnswlib-node is a native module compiled in the Dockerfile native-build stage.
// Dynamic import used to avoid TS resolution issues with native .node bindings.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type HierarchicalNSW = any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _HierarchicalNSW: any = null;

async function getHnswClass(): Promise<HierarchicalNSW> {
  if (!_HierarchicalNSW) {
    const mod = await import('hnswlib-node');

    _HierarchicalNSW = (mod.default ?? mod).HierarchicalNSW;
  }
  return _HierarchicalNSW;
}

const INITIAL_MAX_ELEMENTS = 10_000;
const SAVE_INTERVAL = 50;
const INDEX_S3_KEY = (orgId: string) => `hnsw/${orgId}/index.bin`;
const LABELS_S3_KEY = (orgId: string) => `hnsw/${orgId}/labels.json`;
const TMP_INDEX = (orgId: string) => `/tmp/hnsw-${orgId}.bin`;
const TMP_LABELS = (orgId: string) => `/tmp/hnsw-${orgId}-labels.json`;

export class HnswStore {
  private insertsSinceSave = 0;
  // label (int) ↔ factId (UUID) bidirectional map
  private labelToFactId = new Map<number, string>();
  private factIdToLabel = new Map<string, number>();
  private nextLabel = 0;

  private constructor(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private index: any,
    private readonly orgId: string,
  ) {}

  static async load(
    s3: S3Client,
    keyring: KmsKeyringNode,
    bucket: string,
    orgId: string,
  ): Promise<HnswStore> {
    const HierarchicalNSW = await getHnswClass();

    const store = new HnswStore(new HierarchicalNSW('cosine', EMBED_DIM), orgId);

    const indexBlob = await downloadBlob(s3, keyring, bucket, INDEX_S3_KEY(orgId));
    const labelsBlob = await downloadBlob(s3, keyring, bucket, LABELS_S3_KEY(orgId));

    if (indexBlob && labelsBlob && (await store.restorePersisted(indexBlob, labelsBlob, orgId))) {
      console.log('hnsw loaded', { orgId, elements: store.labelToFactId.size });
    } else {
      store.index = new HierarchicalNSW('cosine', EMBED_DIM);
      store.index.initIndex(INITIAL_MAX_ELEMENTS);
      console.log('hnsw initialized (empty)', { orgId });
    }

    return store;
  }

  private async restorePersisted(
    indexBlob: Buffer,
    labelsBlob: Buffer,
    orgId: string,
  ): Promise<boolean> {
    writeFileSync(TMP_INDEX(orgId), indexBlob);
    try {
      await this.index.readIndex(TMP_INDEX(orgId), INITIAL_MAX_ELEMENTS);
    } catch (err) {
      console.warn('hnsw index unreadable — rebuilding empty', {
        orgId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    } finally {
      unlinkSync(TMP_INDEX(orgId));
    }

    const loadedDim: number = this.index.getNumDimensions();
    if (loadedDim !== EMBED_DIM) {
      console.warn('hnsw index dimension mismatch — rebuilding empty', {
        orgId,
        loadedDim,
        expected: EMBED_DIM,
      });
      return false;
    }

    const labels = JSON.parse(labelsBlob.toString('utf8')) as {
      labelToFactId: [number, string][];
      nextLabel: number;
    };
    this.labelToFactId = new Map(labels.labelToFactId);
    for (const [label, factId] of this.labelToFactId) {
      this.factIdToLabel.set(factId, label);
    }
    this.nextLabel = labels.nextLabel;
    return true;
  }

  insert(factId: string, vector: number[]): void {
    if (this.factIdToLabel.has(factId)) return; // already indexed

    const maxElements: number = this.index.getMaxElements();

    const currentCount: number = this.index.getCurrentCount();
    if (currentCount >= maxElements) {
      this.index.resizeIndex(maxElements * 2);
    }

    const label = this.nextLabel++;

    this.index.addPoint(vector, label);
    this.labelToFactId.set(label, factId);
    this.factIdToLabel.set(factId, label);
    this.insertsSinceSave++;
  }

  search(queryVec: number[], k: number): { factId: string; distance: number }[] {
    const currentCount: number = this.index.getCurrentCount();
    if (currentCount === 0) return [];
    const actualK = Math.min(k, currentCount);

    const result = this.index.searchKnn(queryVec, actualK) as {
      neighbors: number[];
      distances: number[];
    };
    return result.neighbors
      .map((label, i) => ({
        factId: this.labelToFactId.get(label) ?? '',
        distance: result.distances[i] ?? 1,
      }))
      .filter((r) => r.factId !== '');
  }

  async maybeSave(
    s3: S3Client,
    keyring: KmsKeyringNode,
    bucket: string,
    orgId: string,
  ): Promise<void> {
    if (this.insertsSinceSave >= SAVE_INTERVAL) {
      await this.save(s3, keyring, bucket, orgId);
    }
  }

  async save(s3: S3Client, keyring: KmsKeyringNode, bucket: string, orgId: string): Promise<void> {
    this.index.writeIndex(TMP_INDEX(orgId));
    const indexBytes = readFileSync(TMP_INDEX(orgId));
    unlinkSync(TMP_INDEX(orgId));

    const labelsJson = JSON.stringify({
      labelToFactId: [...this.labelToFactId.entries()],
      nextLabel: this.nextLabel,
    });

    await Promise.all([
      uploadBlob(s3, keyring, bucket, INDEX_S3_KEY(orgId), indexBytes, orgId),
      uploadBlob(s3, keyring, bucket, LABELS_S3_KEY(orgId), Buffer.from(labelsJson, 'utf8'), orgId),
    ]);

    this.insertsSinceSave = 0;
    console.log('hnsw saved', { orgId, elements: this.labelToFactId.size });
  }
}

async function downloadBlob(
  s3: S3Client,
  keyring: KmsKeyringNode,
  bucket: string,
  key: string,
): Promise<Buffer | null> {
  try {
    const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    const ciphertextB64 = await obj.Body!.transformToString('utf8');
    const { plaintext } = await decrypt(keyring, Buffer.from(ciphertextB64, 'base64'));
    return Buffer.from(plaintext);
  } catch (err: unknown) {
    // NoSuchKey → fresh start; other errors bubble
    if (err instanceof Error && (err.name === 'NoSuchKey' || err.message.includes('NoSuchKey'))) {
      return null;
    }
    throw err;
  }
}

async function uploadBlob(
  s3: S3Client,
  keyring: KmsKeyringNode,
  bucket: string,
  key: string,
  plaintext: Buffer,
  orgId: string,
): Promise<void> {
  const { result } = await encrypt(keyring, plaintext, {
    encryptionContext: { orgId, key, purpose: 'hnsw' },
  });
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: result.toString('base64'),
      ContentType: 'text/plain',
    }),
  );
}

// suppress unused import warning for node:fs
void existsSync;
void writeFileSync;
