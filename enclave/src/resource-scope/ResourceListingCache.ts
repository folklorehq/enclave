import type { NormalizedResource } from '@folklore/connectors';

export const RESOURCE_LISTING_TTL_MS = 60_000;
export const RESOURCE_LISTING_CACHE_MAX_ENTRIES = 64;

interface CachedListing {
  expiresAt: number;
  resources: NormalizedResource[];
}

/** Provider names stay in this process's memory for one short window and are never logged. */
export class ResourceListingCache {
  private readonly entries = new Map<string, CachedListing>();

  constructor(private readonly now: () => number) {}

  get(orgId: string, sourceKind: string): NormalizedResource[] | undefined {
    const key = this.keyOf(orgId, sourceKind);
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.resources;
  }

  set(orgId: string, sourceKind: string, resources: NormalizedResource[]): void {
    const key = this.keyOf(orgId, sourceKind);
    this.entries.delete(key);
    this.entries.set(key, { expiresAt: this.now() + RESOURCE_LISTING_TTL_MS, resources });
    this.evictOldest();
  }

  private evictOldest(): void {
    while (this.entries.size > RESOURCE_LISTING_CACHE_MAX_ENTRIES) {
      const oldest = this.entries.keys().next();
      if (oldest.done) return;
      this.entries.delete(oldest.value);
    }
  }

  private keyOf(orgId: string, sourceKind: string): string {
    return JSON.stringify([orgId, sourceKind]);
  }
}
