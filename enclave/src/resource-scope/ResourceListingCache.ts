import type { SourceResourceListing } from './ports.js';

export const RESOURCE_LISTING_TTL_MS = 60_000;
export const RESOURCE_LISTING_CACHE_MAX_ENTRIES = 64;

interface CachedListing {
  expiresAt: number;
  listing: SourceResourceListing;
}

/** Provider names stay in this process's memory for one short window and are never logged. */
export class ResourceListingCache {
  private readonly entries = new Map<string, CachedListing>();

  constructor(private readonly now: () => number) {}

  get(orgId: string, sourceKind: string): SourceResourceListing | undefined {
    const key = this.keyOf(orgId, sourceKind);
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.listing;
  }

  set(orgId: string, sourceKind: string, listing: SourceResourceListing): void {
    const key = this.keyOf(orgId, sourceKind);
    this.entries.delete(key);
    this.evictExpired();
    this.entries.set(key, { expiresAt: this.now() + RESOURCE_LISTING_TTL_MS, listing });
    this.evictOldest();
  }

  delete(orgId: string, sourceKind: string): void {
    this.entries.delete(this.keyOf(orgId, sourceKind));
  }

  // Expired names are dropped at the next store, not only when that org is read again.
  private evictExpired(): void {
    const now = this.now();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
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
