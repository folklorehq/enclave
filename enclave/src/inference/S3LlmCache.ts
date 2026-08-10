import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { Cache } from '@folklore/core';
import { InProcessCache } from '@folklore/cache';
import type { EnclaveCrypto } from '../crypto/esdk.js';

export interface S3LlmCacheDeps {
  s3: S3Client;
  crypto: EnclaveCrypto;
  bucket: string;
  orgId: string;
  // Bound on close() waiting out in-flight old-key ops; on expiry close still shreds the RAM front
  // and rejects so teardown propagates fail-closed (replacement assignment refused).
  closeQuiesceTimeoutMs?: number;
}

const LLM_CACHE_PREFIX = 'llm-cache/';
// ~4096-dim embedding JSON (~40KB) × this bound caps the run-local RAM front near 40MB per org.
const RAM_MAX_ENTRIES = 1000;
const CLOSE_QUIESCE_TIMEOUT_MS = 30_000;

// Durable, per-org LLM-output cache: ESDK-sealed in S3 exactly like `facts/`/`hnsw/`, bound to
// (org, cacheKey) so a blob relocated to another org or overwritten onto another key fails to
// decrypt. A run-local RAM LRU keyed by the org-namespaced object key fronts S3, so a
// shared-pool instance can't serve org A's value to org B even in RAM.
export class S3LlmCache implements Cache {
  private readonly ram = new InProcessCache(RAM_MAX_ENTRIES);
  private isClosed = false;
  // Operation lease: close() waits this out so an old-key read/write never completes after
  // retirement. Incremented synchronously at op entry, released in finally.
  private inFlight = 0;
  private readonly closeQuiesceTimeoutMs: number;
  private readonly idleWaiters: Array<() => void> = [];

  constructor(private readonly deps: S3LlmCacheDeps) {
    this.closeQuiesceTimeoutMs = deps.closeQuiesceTimeoutMs ?? CLOSE_QUIESCE_TIMEOUT_MS;
  }

  async get<T>(key: string): Promise<T | null> {
    return this.withLease(async () => {
      this.assertOpen();
      const objectKey = this.objectKey(key);
      const cached = await this.ram.get<string>(objectKey);
      this.assertOpen();
      if (cached !== null) return cached as T;
      const blob = await this.fetch(key);
      this.assertOpen();
      if (blob === null) return null;
      await this.ram.set(objectKey, blob);
      return blob as T;
    });
  }

  async set(key: string, value: unknown): Promise<void> {
    await this.withLease(async () => {
      this.assertOpen();
      const text = value as string;
      await this.ram.set(this.objectKey(key), text);
      this.assertOpen();
      const ciphertext = await this.deps.crypto.encryptLlmCache(Buffer.from(text, 'utf8'), {
        orgId: this.deps.orgId,
        cacheKey: key,
      });
      this.assertOpen();
      await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: this.deps.bucket,
          Key: this.objectKey(key),
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
      return this.ram.del(...keys.map((key) => this.objectKey(key)));
    });
  }

  async close(): Promise<void> {
    if (this.isClosed) return;
    this.isClosed = true;
    // Quiesce: no old-key read/write or RAM mutation may complete after close returns. On timeout
    // we STILL shred the RAM front (values are plain strings — no native use-after-free) and reject
    // so the caller treats the teardown as failed and refuses the replacement assignment.
    if (!(await this.quiesce(this.closeQuiesceTimeoutMs))) {
      await this.ram.close();
      throw new Error('llm_cache_close_timeout');
    }
    await this.ram.close();
  }

  private async fetch(key: string): Promise<string | null> {
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: this.objectKey(key) }),
      );
      this.assertOpen();
      const raw = await obj.Body!.transformToByteArray();
      this.assertOpen();
      const ciphertext = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      const plaintext = await this.deps.crypto.decryptLlmCache(ciphertext, {
        orgId: this.deps.orgId,
        cacheKey: key,
      });
      this.assertOpen();
      return plaintext.toString('utf8');
    } catch (err) {
      if (err instanceof NoSuchKey) return null;
      throw err;
    }
  }

  private objectKey(key: string): string {
    return `${LLM_CACHE_PREFIX}${this.deps.orgId}/${key}`;
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
