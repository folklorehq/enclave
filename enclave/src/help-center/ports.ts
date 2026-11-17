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
