import type { NormalizedResource } from '@folklore/connectors';

export interface SourceResourceListing {
  connectionKey: string;
  resources: NormalizedResource[];
}

export interface SourceResourceLister {
  listResources(input: { orgId: string; sourceKind: string }): Promise<SourceResourceListing>;
  connectionKey(input: { orgId: string; sourceKind: string }): Promise<string>;
}
