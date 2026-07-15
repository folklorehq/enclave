import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { Cache } from '@folklore/core';
import { InProcessCache } from '@folklore/cache';
import type { EnclaveCrypto } from '../crypto/esdk.js';

export interface S3LlmCacheDeps {
  s3: S3Client;
  crypto: EnclaveCrypto;
  bucket: string;
  orgId: string;
}

const LLM_CACHE_PREFIX = 'llm-cache/';
// ~4096-dim embedding JSON (~40KB) × this bound caps the run-local RAM front near 40MB per org.
const RAM_MAX_ENTRIES = 1000;

// Durable, per-org LLM-output cache: ESDK-sealed in S3 exactly like `facts/`/`hnsw/`, bound to
// (org, cacheKey) so a blob relocated to another org or overwritten onto another key fails to
// decrypt (ADL #12). A run-local RAM LRU keyed by the org-namespaced object key fronts S3, so a
// shared-pool instance (ADL #61) can't serve org A's value to org B even in RAM.
export class S3LlmCache implements Cache {
  private readonly ram = new InProcessCache(RAM_MAX_ENTRIES);

  constructor(private readonly deps: S3LlmCacheDeps) {}

  async get<T>(key: string): Promise<T | null> {
    const objectKey = this.objectKey(key);
    const cached = await this.ram.get<string>(objectKey);
    if (cached !== null) return cached as T;
    const blob = await this.fetch(key);
    if (blob === null) return null;
    await this.ram.set(objectKey, blob);
    return blob as T;
  }

  async set(key: string, value: unknown): Promise<void> {
    const text = value as string;
    await this.ram.set(this.objectKey(key), text);
    const ciphertext = await this.deps.crypto.encryptLlmCache(Buffer.from(text, 'utf8'), {
      orgId: this.deps.orgId,
      cacheKey: key,
    });
    await this.deps.s3.send(
      new PutObjectCommand({
        Bucket: this.deps.bucket,
        Key: this.objectKey(key),
        Body: ciphertext.toString('base64'),
        ContentType: 'text/plain',
      }),
    );
  }

  // Content-addressed blobs are immutable (same input → same output), so invalidation only clears
  // the RAM front; the durable S3 object stays.
  async del(...keys: string[]): Promise<number> {
    return this.ram.del(...keys.map((key) => this.objectKey(key)));
  }

  async close(): Promise<void> {
    await this.ram.close();
  }

  private async fetch(key: string): Promise<string | null> {
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: this.objectKey(key) }),
      );
      const raw = await obj.Body!.transformToByteArray();
      const ciphertext = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      const plaintext = await this.deps.crypto.decryptLlmCache(ciphertext, {
        orgId: this.deps.orgId,
        cacheKey: key,
      });
      return plaintext.toString('utf8');
    } catch (err) {
      if (err instanceof NoSuchKey) return null;
      throw err;
    }
  }

  private objectKey(key: string): string {
    return `${LLM_CACHE_PREFIX}${this.deps.orgId}/${key}`;
  }
}
