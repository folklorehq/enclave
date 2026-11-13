import type { IndexResidencyManager } from '../hnsw/IndexResidencyManager.js';
import type { EnclaveTitleCatalog } from './EnclaveTitleCatalog.js';
import type { TitleIndex } from './TitleIndex.js';

export interface TitleEvictionDeps {
  catalog: () => Pick<EnclaveTitleCatalog, 'forgetTenant'> | undefined;
  residency: Pick<IndexResidencyManager<TitleIndex>, 'evict'>;
  graphCache: () => { evictTitleCaches(orgId: string): Promise<void> } | undefined;
}

/** Drops every decrypted title a tenant has in RAM: the catalog's state, the resident index and the graph cache. */
export class TitleEviction {
  constructor(private readonly deps: TitleEvictionDeps) {}

  async evict(orgId: string): Promise<void> {
    this.deps.catalog()?.forgetTenant(orgId);
    await Promise.all([
      this.deps.residency.evict(orgId),
      this.deps.graphCache()?.evictTitleCaches(orgId),
    ]);
  }
}
