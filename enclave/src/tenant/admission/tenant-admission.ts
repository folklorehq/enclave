import type { TenantAdmission } from '@folklore/api';

export interface TenantAdmissionChecks {
  isHaltedNow: (tenantId: string) => Promise<boolean>;
  isFenced: (tenantId: string) => boolean;
}

export function createTenantAdmission(checks: TenantAdmissionChecks): TenantAdmission {
  return async (tenantId) => {
    if (await checks.isHaltedNow(tenantId)) return false;
    // Read after the awaited halt check so a fence raised while it was pending is still seen.
    return !checks.isFenced(tenantId);
  };
}
