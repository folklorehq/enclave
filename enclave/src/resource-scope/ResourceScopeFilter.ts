import { isPausableSourceKind } from '@folklore/contracts';
import { ADMIT_ALL, admissionOf, type ResourceAdmission } from './resource-admission.js';
import { ResourceScopeUnavailableError } from './resource-scope-errors.js';
import type { ResourceScope } from './ResourceScopeStore.js';

export const RESOURCE_SCOPE_CACHE_TTL_MS = 60_000;

export interface ResourceScopeFilterDeps {
  orgId: string;
  readScope(sourceKind: string): Promise<ResourceScope>;
  now?: () => number;
}

interface CachedScope {
  scope: ResourceScope;
  expiresAt: number;
}

/** Per-process scope cache for webhook facts; a failed read throws and is never cached. */
export class ResourceScopeFilter {
  private readonly cache = new Map<string, CachedScope>();

  constructor(private readonly deps: ResourceScopeFilterDeps) {}

  async predicateFor(sourceKind: string): Promise<ResourceAdmission> {
    if (!isPausableSourceKind(sourceKind)) return ADMIT_ALL;
    return admissionOf(await this.scopeOf(sourceKind));
  }

  invalidate(sourceKind: string): void {
    this.cache.delete(this.cacheKey(sourceKind));
  }

  private async scopeOf(sourceKind: string): Promise<ResourceScope> {
    const key = this.cacheKey(sourceKind);
    const now = (this.deps.now ?? Date.now)();
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > now) return cached.scope;
    try {
      const scope = await this.deps.readScope(sourceKind);
      this.cache.set(key, { scope, expiresAt: now + RESOURCE_SCOPE_CACHE_TTL_MS });
      return scope;
    } catch {
      this.cache.delete(key);
      throw new ResourceScopeUnavailableError();
    }
  }

  private cacheKey(sourceKind: string): string {
    return `${this.deps.orgId}\u0000${sourceKind}`;
  }
}
