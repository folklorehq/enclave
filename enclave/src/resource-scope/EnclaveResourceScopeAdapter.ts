import type { S3Client } from '@aws-sdk/client-s3';
import type { NormalizedResource } from '@folklore/connectors';
import type {
  ResourceScopePausedResult,
  ResourceScopePort,
  ResourceScopeWriteResult,
} from '@folklore/api';
import {
  type ResourceScopeRequest,
  type ResourceScopeResponse,
  type ScopeResourcePage,
  type ScopeResourcePageQuery,
} from '@folklore/contracts';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  ResourceScopeInvalidError,
  ResourceScopeUnavailableError,
} from './resource-scope-errors.js';
import { ResourceListingCache } from './ResourceListingCache.js';
import type { ResourceScopeFilter } from './ResourceScopeFilter.js';
import type { ResourceScope } from './ResourceScopeStore.js';
import { TenantResourceScope } from './TenantResourceScope.js';

const PAGE_SIZE = 100;
const PROVIDER_UNAVAILABLE = 'source_provider_unavailable';

export interface SourceResourceLister {
  listResources(input: { orgId: string; sourceKind: string }): Promise<NormalizedResource[]>;
}

interface TenantScopeContext {
  processedOutputsScope(): { crypto: EnclaveCrypto; bucket: string; deploymentId: string };
  resourceScope?: Pick<ResourceScopeFilter, 'invalidate'>;
}

export interface EnclaveResourceScopeAdapterDeps {
  s3: S3Client;
  resolveTenant(orgId: string): TenantScopeContext;
  connectors: SourceResourceLister;
  now?: () => number;
}

interface ScopeTarget {
  orgId: string;
  sourceKind: string;
}

/** Ids only cross this class's boundary to the store; names go to the admin's response and nowhere else. */
export class EnclaveResourceScopeAdapter implements ResourceScopePort {
  private readonly listings: ResourceListingCache;

  constructor(private readonly deps: EnclaveResourceScopeAdapterDeps) {
    this.listings = new ResourceListingCache(deps.now ?? Date.now);
  }

  async listResources(
    input: ScopeTarget & { query: ScopeResourcePageQuery },
  ): Promise<ScopeResourcePage> {
    const offset = this.decodeCursor(input.query.cursor);
    const needle = input.query.query?.toLocaleLowerCase();
    const named = (await this.listLive(input)).map((resource) => ({
      id: resource.externalId,
      name: resource.displayName ?? resource.externalId,
      isPublic: resource.isPublic,
    }));
    const matching = needle
      ? named.filter((item) => item.name.toLocaleLowerCase().includes(needle))
      : named;
    matching.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    const items = matching.slice(offset, offset + PAGE_SIZE);
    const nextOffset = offset + items.length;
    return {
      items,
      nextCursor: nextOffset < matching.length ? this.encodeCursor(nextOffset) : null,
    };
  }

  async readScope(input: ScopeTarget): Promise<ResourceScopeResponse> {
    return this.responseOf(await this.storeFor(input.orgId).store.read(input.sourceKind));
  }

  async writeScope(
    input: ScopeTarget & { scope: ResourceScopeRequest },
  ): Promise<ResourceScopeWriteResult> {
    const { orgId, sourceKind, scope } = input;
    const { store, tenant } = this.storeFor(orgId);
    const previous = await store.read(sourceKind);
    if (scope.mode === 'selected') {
      await this.requireListed(input, this.newlySelected(previous, scope.resourceIds));
    }
    const written = await store.write({
      sourceKind,
      expectedRevision: scope.expectedRevision,
      mode: scope.mode,
      resourceIds: scope.mode === 'selected' ? scope.resourceIds : [],
    });
    tenant.resourceScope?.invalidate(sourceKind);
    return { scope: this.responseOf(written), ...this.countsOf(previous, written) };
  }

  async setPaused(
    input: ScopeTarget & { paused: boolean; expectedRevision: number },
  ): Promise<ResourceScopePausedResult> {
    const { store, tenant } = this.storeFor(input.orgId);
    const result = await store.setPaused({
      sourceKind: input.sourceKind,
      expectedRevision: input.expectedRevision,
      paused: input.paused,
    });
    tenant.resourceScope?.invalidate(input.sourceKind);
    return { scope: this.responseOf(result.scope), changed: result.changed };
  }

  private storeFor(orgId: string): { store: TenantResourceScope; tenant: TenantScopeContext } {
    try {
      const tenant = this.deps.resolveTenant(orgId);
      const scope = tenant.processedOutputsScope();
      return { store: new TenantResourceScope({ s3: this.deps.s3, orgId, scope }), tenant };
    } catch {
      throw new ResourceScopeUnavailableError();
    }
  }

  private newlySelected(previous: ResourceScope, ids: readonly string[]): string[] {
    const stored = new Set(previous.resourceIds);
    return ids.filter((id) => !stored.has(id));
  }

  // A stored id may have left the provider since it was chosen, so only a new id has to be listed.
  private async requireListed(target: ScopeTarget, ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    const listed = new Set((await this.listLive(target)).map((resource) => resource.externalId));
    if (!ids.every((id) => listed.has(id))) throw new ResourceScopeInvalidError();
  }

  private async listLive(target: ScopeTarget): Promise<NormalizedResource[]> {
    const cached = this.listings.get(target.orgId, target.sourceKind);
    if (cached) return cached;
    try {
      const resources = await this.deps.connectors.listResources({
        orgId: target.orgId,
        sourceKind: target.sourceKind,
      });
      this.listings.set(target.orgId, target.sourceKind, resources);
      return resources;
    } catch {
      throw new Error(PROVIDER_UNAVAILABLE);
    }
  }

  private responseOf(scope: ResourceScope): ResourceScopeResponse {
    return {
      revision: scope.revision,
      mode: scope.mode,
      resourceIds: scope.resourceIds,
      paused: scope.paused,
    };
  }

  private countsOf(
    previous: ResourceScope,
    next: ResourceScope,
  ): Pick<ResourceScopeWriteResult, 'addedCount' | 'removedCount'> {
    const before = new Set(previous.resourceIds);
    const after = new Set(next.resourceIds);
    return {
      addedCount: next.resourceIds.filter((id) => !before.has(id)).length,
      removedCount: previous.resourceIds.filter((id) => !after.has(id)).length,
    };
  }

  private decodeCursor(cursor: string | undefined): number {
    if (!cursor) return 0;
    try {
      const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
        offset?: unknown;
      };
      if (
        Object.keys(parsed).length !== 1 ||
        !Number.isSafeInteger(parsed.offset) ||
        (parsed.offset as number) < 0
      ) {
        throw new Error('invalid');
      }
      return parsed.offset as number;
    } catch {
      throw new ResourceScopeInvalidError();
    }
  }

  private encodeCursor(offset: number): string {
    return Buffer.from(JSON.stringify({ offset }), 'utf8').toString('base64url');
  }
}
