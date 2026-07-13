import type { TenantContext } from './tenant-context.js';

// Content-free (ADL #18): a tenant id is a content-free identifier, never customer data.
export class UnknownTenantError extends Error {
  constructor(readonly tenantId: string) {
    super(`no tenant context assigned for ${tenantId}`);
    this.name = 'UnknownTenantError';
  }
}

// Maps tenantId → its own TenantContext. There is no global keyring: crypto/storage callers
// resolve a context here and use only that context's key material, so adding contexts later can
// never accidentally share a keyring across tenants (shared-tier design §2.2 point 1). Stage 1
// holds exactly one context, built from TENANT_ID.
export class TenantRegistry {
  private readonly contexts = new Map<string, TenantContext>();

  register(context: TenantContext): void {
    this.contexts.set(context.tenantId, context);
  }

  has(tenantId: string): boolean {
    return this.contexts.has(tenantId);
  }

  get(tenantId: string): TenantContext {
    const context = this.contexts.get(tenantId);
    if (!context) throw new UnknownTenantError(tenantId);
    return context;
  }
}
