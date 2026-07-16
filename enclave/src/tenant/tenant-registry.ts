import type { TenantContext } from './tenant-context.js';

// Content-free (ADL #18): a tenant id is a content-free identifier, never customer data.
export class UnknownTenantError extends Error {
  constructor(readonly tenantId: string) {
    super(`no tenant context assigned for ${tenantId}`);
    this.name = 'UnknownTenantError';
  }
}

// Maps tenantId → its own TenantContext. There is no global keyring: crypto/storage callers
// resolve a context here and use only that context's key material, so no tenant can ever reach
// another's keyring (shared-tier design §2.2 point 1). Holds 1..N contexts — a dedicated box is
// simply the registry with one assigned tenant (design §6.1: dedicated is the default tier).
export class TenantRegistry {
  private readonly contexts = new Map<string, TenantContext>();

  register(context: TenantContext): void {
    this.contexts.set(context.tenantId, context);
  }

  // Returns the dropped context (or undefined) so the caller can zeroize its key material on a
  // reassignment teardown (§2.2 point 5) — the registry only unmaps; it never decides zeroing.
  remove(tenantId: string): TenantContext | undefined {
    const context = this.contexts.get(tenantId);
    this.contexts.delete(tenantId);
    return context;
  }

  has(tenantId: string): boolean {
    return this.contexts.has(tenantId);
  }

  get(tenantId: string): TenantContext {
    const context = this.contexts.get(tenantId);
    if (!context) throw new UnknownTenantError(tenantId);
    return context;
  }

  all(): TenantContext[] {
    return [...this.contexts.values()];
  }

  get size(): number {
    return this.contexts.size;
  }
}
