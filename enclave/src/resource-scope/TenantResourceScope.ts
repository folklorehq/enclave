import type { S3Client } from '@aws-sdk/client-s3';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  ResourceScopeStore,
  type ResourceScope,
  type ResourceScopeBackfill,
} from './ResourceScopeStore.js';

export interface TenantResourceScopeWrite {
  sourceKind: string;
  expectedRevision: number;
  mode: 'all' | 'selected';
  resourceIds: readonly string[];
}

export interface TenantResourceScopeTransition {
  sourceKind: string;
  expectedRevision: number;
  from: Exclude<ResourceScopeBackfill, 'none'>;
  to: Exclude<ResourceScopeBackfill, 'owed'>;
}

export interface TenantResourceScopePause {
  sourceKind: string;
  expectedRevision: number;
  paused: boolean;
}

export interface TenantResourceScopeLocation {
  s3: S3Client;
  orgId: string;
  scope: { crypto: EnclaveCrypto; bucket: string; deploymentId: string };
}

/** The scope store bound to one tenant deployment, so callers name only the source kind. */
export class TenantResourceScope {
  private readonly store: ResourceScopeStore;

  constructor(private readonly location: TenantResourceScopeLocation) {
    this.store = new ResourceScopeStore({
      s3: location.s3,
      bucket: location.scope.bucket,
      crypto: location.scope.crypto,
    });
  }

  read(sourceKind: string): Promise<ResourceScope> {
    return this.store.read(this.key(sourceKind));
  }

  write(input: TenantResourceScopeWrite): Promise<ResourceScope> {
    return this.store.write({ ...this.key(input.sourceKind), ...input });
  }

  setPaused(input: TenantResourceScopePause): Promise<{ scope: ResourceScope; changed: boolean }> {
    return this.store.setPaused({ ...this.key(input.sourceKind), ...input });
  }

  transitionBackfill(input: TenantResourceScopeTransition): Promise<ResourceScope> {
    return this.store.transitionBackfill({ ...this.key(input.sourceKind), ...input });
  }

  private key(sourceKind: string) {
    return {
      orgId: this.location.orgId,
      deploymentId: this.location.scope.deploymentId,
      sourceKind,
    };
  }
}
