import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import type { LlmCacheNamer } from './llm-cache.js';
import { LlmRamFront, type LlmRamFrontOptions } from './LlmRamFront.js';
import { float32Vector, parseVector, type LlmOperationCache } from './vector-cache.js';

export interface S3LlmCacheDeps {
  s3: S3Client;
  crypto: EnclaveCrypto;
  bucket: string;
  orgId: string;
  namer: LlmCacheNamer;
  // Bound on close() waiting out in-flight old-key ops; on expiry close still shreds the RAM front
  // and rejects so teardown propagates fail-closed (replacement assignment refused).
  closeQuiesceTimeoutMs?: number;
  ramFront?: LlmRamFrontOptions;
}

const LLM_CACHE_PREFIX = 'llm-cache/';
// Keyed names live under v2/; purging the unread legacy objects is not yet wired.
const KEYED_NAME_SEGMENT = 'v2/';
const CLOSE_QUIESCE_TIMEOUT_MS = 30_000;

// Objects are named by the tenant's keyed HMAC, so a host that lists the bucket sees no input digest.
export class S3LlmCache implements LlmOperationCache {
  private readonly ram: LlmRamFront;
  private isClosed = false;
  // Operation lease: close() waits this out so an old-key read/write never completes after
  // retirement. Incremented synchronously at op entry, released in finally.
  private inFlight = 0;
  private readonly closeQuiesceTimeoutMs: number;
  private readonly idleWaiters: Array<() => void> = [];

  constructor(private readonly deps: S3LlmCacheDeps) {
    this.closeQuiesceTimeoutMs = deps.closeQuiesceTimeoutMs ?? CLOSE_QUIESCE_TIMEOUT_MS;
    this.ram = new LlmRamFront(deps.ramFront);
  }

  async get<T>(key: string): Promise<T | null> {
    return this.withLease(async () => {
      this.assertOpen();
      const name = this.deps.namer.llmCacheName(key);
      const objectKey = this.objectKey(name);
      const cached = this.ram.get(objectKey);
      if (cached !== undefined) return S3LlmCache.asText(cached) as T;
      const blob = await this.fetch(name);
      this.assertOpen();
      if (blob === null) return null;
      this.ram.set(objectKey, blob);
      return blob as T;
    });
  }

  async getVector(key: string): Promise<number[] | null> {
    return this.withLease(async () => {
      this.assertOpen();
      const name = this.deps.namer.llmCacheName(key);
      const objectKey = this.objectKey(name);
      const cached = this.ram.get(objectKey);
      if (cached instanceof Float32Array) return Array.from(cached);
      const blob = typeof cached === 'string' ? cached : await this.fetch(name);
      this.assertOpen();
      if (blob === null) return null;
      const vector = parseVector(blob);
      if (vector === null) return null;
      this.ram.set(objectKey, Float32Array.from(vector));
      return vector;
    });
  }

  async set(key: string, value: unknown): Promise<void> {
    const text = value as string;
    await this.persist(key, text, text);
  }

  async setVector(key: string, vector: readonly number[]): Promise<void> {
    const rounded = float32Vector(vector);
    await this.persist(key, JSON.stringify(rounded), Float32Array.from(rounded));
  }

  private async persist(key: string, text: string, ramEntry: string | Float32Array): Promise<void> {
    await this.withLease(async () => {
      this.assertOpen();
      const name = this.deps.namer.llmCacheName(key);
      this.ram.set(this.objectKey(name), ramEntry);
      this.assertOpen();
      const ciphertext = await this.deps.crypto.encryptLlmCache(Buffer.from(text, 'utf8'), {
        orgId: this.deps.orgId,
        objectName: name,
      });
      this.assertOpen();
      await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: this.deps.bucket,
          Key: this.objectKey(name),
          Body: ciphertext.toString('base64'),
          ContentType: 'text/plain',
        }),
      );
      // Defense in depth: the lease is the primary barrier (close waits this op out), this check
      // rejects completion once retirement is signalled even if a future caller skips the lease.
      this.assertOpen();
    });
  }

  // Content-addressed blobs are immutable (same input → same output), so invalidation only clears
  // the RAM front; the durable S3 object stays.
  async del(...keys: string[]): Promise<number> {
    return this.withLease(async () => {
      this.assertOpen();
      let deleted = 0;
      for (const key of keys) {
        if (this.ram.delete(this.objectKey(this.deps.namer.llmCacheName(key)))) deleted += 1;
      }
      return deleted;
    });
  }

  async close(): Promise<void> {
    if (this.isClosed) return;
    this.isClosed = true;
    // Quiesce: no old-key read/write or RAM mutation may complete after close returns. On timeout
    // we STILL shred the RAM front (values are strings or typed arrays — no native use-after-free) and reject
    // so the caller treats the teardown as failed and refuses the replacement assignment.
    if (!(await this.quiesce(this.closeQuiesceTimeoutMs))) {
      this.ram.clear();
      throw new Error('llm_cache_close_timeout');
    }
    this.ram.clear();
  }

  private async fetch(name: string): Promise<string | null> {
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: this.objectKey(name) }),
      );
      this.assertOpen();
      const raw = await obj.Body!.transformToByteArray();
      this.assertOpen();
      const ciphertext = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      const plaintext = await this.deps.crypto.decryptLlmCache(ciphertext, {
        orgId: this.deps.orgId,
        objectName: name,
      });
      this.assertOpen();
      return plaintext.toString('utf8');
    } catch (err) {
      if (err instanceof NoSuchKey) return null;
      throw err;
    }
  }

  private static asText(entry: string | Float32Array): string {
    return typeof entry === 'string' ? entry : JSON.stringify(Array.from(entry));
  }

  private objectKey(name: string): string {
    return `${LLM_CACHE_PREFIX}${this.deps.orgId}/${KEYED_NAME_SEGMENT}${name}`;
  }

  private assertOpen(): void {
    if (this.isClosed) throw new Error('llm_cache_closed');
  }

  private async withLease<T>(run: () => Promise<T>): Promise<T> {
    this.inFlight += 1;
    try {
      return await run();
    } finally {
      this.inFlight -= 1;
      this.notifyIdle();
    }
  }

  private async quiesce(timeoutMs: number): Promise<boolean> {
    if (this.inFlight === 0) return true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs);
    });
    const idle = new Promise<boolean>((resolve) => {
      this.idleWaiters.push(() => resolve(true));
    });
    const settled = await Promise.race([idle, timedOut]);
    if (timer) clearTimeout(timer);
    return settled;
  }

  private notifyIdle(): void {
    if (this.inFlight !== 0) return;
    const waiters = this.idleWaiters.splice(0);
    for (const wake of waiters) wake();
  }
}
