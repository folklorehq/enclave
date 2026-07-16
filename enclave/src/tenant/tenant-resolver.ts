import { ForbiddenError } from '@folklore/errors';
import type { TenantContext } from './tenant-context.js';
import type { TenantRegistry } from './tenant-registry.js';

export type ResolveTenant = (orgId: string) => TenantContext;

// Per-request tenant selection (shared-tier design §4.2): the single choke point where a request's
// verified orgId picks its key material. Fails closed with a 403-mapping AppError when the orgId is
// not in this enclave's assigned set — BEFORE any keyring/index is reachable — so a token for an
// unassigned tenant can never touch another tenant's crypto (§2.2 compartmentalization invariant).
export function createTenantResolver(registry: TenantRegistry): ResolveTenant {
  return (orgId: string): TenantContext => {
    if (!registry.has(orgId)) {
      throw new ForbiddenError(`org ${orgId} is not assigned to this enclave`);
    }
    return registry.get(orgId);
  };
}
