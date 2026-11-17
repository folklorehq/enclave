import type { TenantContext } from '../tenant/tenant-context.js';
import { HelpCenterNotActivatedError } from './help-center-source-errors.js';
import type { HelpCenterAdapterDeps, HelpCenterTenantActivation } from './ports.js';

export interface ActivatedTenant {
  readonly activation: HelpCenterTenantActivation;
  readonly tenant: TenantContext;
}

// Activation is checked first, on every call; a tenant that is gone surfaces only the adapter's closed code.
export function resolveActivatedTenant(
  deps: HelpCenterAdapterDeps,
  orgId: string,
  unavailableCode: string,
): ActivatedTenant | null {
  try {
    const activation = deps.activation.forTenant(orgId);
    return activation === null ? null : { activation, tenant: deps.resolveTenant(orgId) };
  } catch {
    throw new Error(unavailableCode);
  }
}

export function requireActivatedTenant(
  deps: HelpCenterAdapterDeps,
  orgId: string,
  unavailableCode: string,
): ActivatedTenant {
  const resolved = resolveActivatedTenant(deps, orgId, unavailableCode);
  if (resolved === null) throw new HelpCenterNotActivatedError();
  return resolved;
}
