import type { Logger } from '@folklore/core';
import type { EntitlementSyncOutcome } from '@folklore/wiki';
import { TenantPeriodicRunner, type TenantRunnerEvents } from '../tenant/TenantPeriodicRunner.js';

const SETTLED_OUTCOMES: ReadonlySet<TenantProjectionOutcome> = new Set([
  'applied',
  'skipped_stale',
]);
const PROJECTION_EVENTS: TenantRunnerEvents = {
  pass: 'entitlement_projection_tenant_pass',
  skipped: 'entitlement_projection_tenant_skipped',
  failed: 'entitlement_projection_tenant_failed',
  passFailed: 'entitlement_projection_pass_failed',
};

export interface ProjectionTenant {
  readonly tenantId: string;
  readonly tenantDeploymentId: string;
}

export type TenantProjectionOutcome = EntitlementSyncOutcome | 'database_unavailable';

export interface TenantEntitlementProjectionRunnerDeps {
  readonly tenants: () => readonly ProjectionTenant[];
  readonly beginTenant: (tenantId: string) => Promise<(() => void) | undefined>;
  readonly syncTenant: (tenant: ProjectionTenant) => Promise<TenantProjectionOutcome>;
  readonly logger: Logger;
  readonly now?: () => number;
}

/** Keeps each assigned tenant's entitlement projection current, one tenant at a time. */
export class TenantEntitlementProjectionRunner extends TenantPeriodicRunner<
  ProjectionTenant,
  TenantProjectionOutcome
> {
  constructor(deps: TenantEntitlementProjectionRunnerDeps) {
    super({
      tenants: deps.tenants,
      beginTenant: deps.beginTenant,
      runTenant: deps.syncTenant,
      settledOutcomes: SETTLED_OUTCOMES,
      events: PROJECTION_EVENTS,
      logger: deps.logger,
      ...(deps.now === undefined ? {} : { now: deps.now }),
    });
  }
}
