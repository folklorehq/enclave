import type { HelpCenterRepositoryPort } from '@folklore/api';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';

export interface HelpCenterTenantActivation {
  readonly orgId: string;
  readonly signingKeyEpoch: number;
  readonly firstActivatedAt: string;
  readonly reactivationGeneration: number;
  readonly stagingBucket: string;
  readonly accountId: string;
}

export interface HelpCenterActivationPort {
  forTenant(orgId: string): HelpCenterTenantActivation | null;
}

export interface HelpCenterAdapterDeps {
  readonly resolveTenant: ResolveTenant;
  readonly activation: HelpCenterActivationPort;
}

export interface HelpCenterAttestedFactRow {
  readonly factId: string;
  readonly bodyHash: string;
  readonly sourceKind: string;
  readonly resourceExternalId: string;
  readonly sensitivityLevel: string;
  readonly origin: string;
  readonly ownerAccountId: string | null;
  readonly mac: string;
}

export interface HelpCenterVerifierFact {
  readonly factId: string;
  readonly bodyS3Key: string;
  // Also true while a source deletion of this fact is pending.
  readonly deleted: boolean;
  readonly superseded: boolean;
  // A fail-closed superset of the fact's theme membership.
  readonly themeIds: readonly string[];
  readonly attestations: readonly HelpCenterAttestedFactRow[];
}

export interface HelpCenterVerifierReadPort extends Pick<
  HelpCenterRepositoryPort,
  'listDesignations' | 'listResourceVisibility'
> {
  facts(orgId: string, factIds: readonly string[]): Promise<readonly HelpCenterVerifierFact[]>;
  blockedThemeIds(orgId: string): Promise<readonly string[] | null>;
}
