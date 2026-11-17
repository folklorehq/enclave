// UNWIRED: no composition root builds this yet.
import type { HelpCenterDesignatableSource, HelpCenterSourceResolverPort } from '@folklore/api';
import type { NormalizedResource } from '@folklore/connectors';
import { resourceScopeUnitFor, type ResourceScopeUnit } from '@folklore/contracts';
import { helpCenterSourceErrorCodeSchema } from '@folklore/contracts/help-center';
import type { KeyedPlaceRef } from '@folklore/utils';
import { SourceIdKeyer } from '../pipeline/SourceIdKeyer.js';
import type { SourceResourceLister } from '../resource-scope/ports.js';
import { ResourceListingCache } from '../resource-scope/ResourceListingCache.js';
import { requireActivatedTenant } from './activated-tenant.js';
import {
  HelpCenterPlaceKeyUnavailableError,
  HelpCenterSourceKindUnsupportedError,
  HelpCenterSourceProviderUnavailableError,
} from './help-center-source-errors.js';
import type { HelpCenterAdapterDeps } from './ports.js';

const PLACE_KEY_UNAVAILABLE = helpCenterSourceErrorCodeSchema.enum.place_key_unavailable;

export interface EnclaveHelpCenterSourceResolverDeps extends HelpCenterAdapterDeps {
  readonly connectors: SourceResourceLister;
  readonly now?: () => number;
}

// Provider ids and names stay in this process; only org-keyed refs leave it.
export class EnclaveHelpCenterSourceResolver implements HelpCenterSourceResolverPort {
  private readonly listings: ResourceListingCache;

  constructor(private readonly deps: EnclaveHelpCenterSourceResolverDeps) {
    this.listings = new ResourceListingCache(deps.now ?? Date.now);
  }

  async listDesignatable(
    orgId: string,
    sourceKind: string,
  ): Promise<readonly HelpCenterDesignatableSource[]> {
    const unit = this.unitFor(sourceKind);
    const keyer = new SourceIdKeyer(this.entityKeyFor(orgId), orgId);
    try {
      const resources = await this.listLive(orgId, sourceKind);
      return resources.map((resource) => ({
        placeRef: keyer.place(sourceKind, resource.externalId),
        resourceType: unit,
        isPublic: resource.isPublic,
      }));
    } finally {
      keyer.zeroize();
    }
  }

  async resolve(
    orgId: string,
    sourceKind: string,
    placeRef: KeyedPlaceRef,
  ): Promise<HelpCenterDesignatableSource | null> {
    const listed = await this.listDesignatable(orgId, sourceKind);
    return listed.find((source) => source.placeRef === placeRef) ?? null;
  }

  private unitFor(sourceKind: string): ResourceScopeUnit {
    const unit = resourceScopeUnitFor(sourceKind);
    if (unit === undefined) throw new HelpCenterSourceKindUnsupportedError();
    return unit;
  }

  private entityKeyFor(orgId: string): Buffer {
    const { tenant } = requireActivatedTenant(this.deps, orgId, PLACE_KEY_UNAVAILABLE);
    const key = tenant.entityKey();
    if (key === null) throw new HelpCenterPlaceKeyUnavailableError();
    return key;
  }

  // Same connection check as the resource-scope adapter's live listing; the lister's own error text is dropped.
  private async listLive(orgId: string, sourceKind: string): Promise<NormalizedResource[]> {
    try {
      const cached = this.listings.get(orgId, sourceKind);
      if (
        cached &&
        cached.connectionKey === (await this.deps.connectors.connectionKey({ orgId, sourceKind }))
      ) {
        return cached.resources;
      }
      this.listings.delete(orgId, sourceKind);
      const listing = await this.deps.connectors.listResources({ orgId, sourceKind });
      this.listings.set(orgId, sourceKind, listing);
      return listing.resources;
    } catch {
      throw new HelpCenterSourceProviderUnavailableError();
    }
  }
}
