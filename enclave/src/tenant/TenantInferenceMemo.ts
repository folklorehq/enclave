import type { S3Client } from '@aws-sdk/client-s3';
import type { LlmCacheNamer } from '../inference/llm-cache.js';
import { S3LlmCache } from '../inference/S3LlmCache.js';
import type { TenantContext } from './tenant-context.js';
import type { ResolveTenant } from './tenant-resolver.js';

export interface TenantInferenceMemoDeps<T> {
  s3: S3Client;
  resolveTenant: ResolveTenant;
  bucketFor: (orgId: string, tenant: TenantContext) => string;
  build: (orgId: string, tenant: TenantContext, cache: S3LlmCache) => T;
}

interface MemoEntry<T> {
  tenant: TenantContext;
  cache: S3LlmCache;
  value: T;
}

// One cached inference per org, rebuilt whenever the org resolves to a different context.
export class TenantInferenceMemo<T> {
  private readonly entries = new Map<string, MemoEntry<T>>();

  constructor(private readonly deps: TenantInferenceMemoDeps<T>) {}

  get(orgId: string): T {
    const tenant = this.deps.resolveTenant(orgId);
    const current = this.entries.get(orgId);
    if (current?.tenant === tenant) return current.value;
    if (current) this.retireStale(orgId, current);
    return this.build(orgId, tenant).value;
  }

  take(orgId: string): S3LlmCache | undefined {
    const entry = this.entries.get(orgId);
    this.entries.delete(orgId);
    return entry?.cache;
  }

  async evict(orgId: string): Promise<void> {
    await this.take(orgId)?.close();
  }

  orgIds(): string[] {
    return [...this.entries.keys()];
  }

  private build(orgId: string, tenant: TenantContext): MemoEntry<T> {
    const cache = new S3LlmCache({
      s3: this.deps.s3,
      crypto: tenant.crypto,
      bucket: this.deps.bucketFor(orgId, tenant),
      orgId,
      namer: this.namerFor(orgId),
    });
    const entry = { tenant, cache, value: this.deps.build(orgId, tenant, cache) };
    this.entries.set(orgId, entry);
    return entry;
  }

  // Resolved per call, so a cache held across a context swap names through the live context.
  private namerFor(orgId: string): LlmCacheNamer {
    return { llmCacheName: (cacheKey) => this.deps.resolveTenant(orgId).llmCacheName(cacheKey) };
  }

  // Nothing waits on retirement; close() shreds the RAM front even when its quiesce times out.
  private retireStale(orgId: string, entry: MemoEntry<T>): void {
    this.entries.delete(orgId);
    void entry.cache.close().catch(() => {});
  }
}
