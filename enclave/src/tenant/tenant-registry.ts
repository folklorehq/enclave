import type { TenantContext } from './tenant-context.js';
import type { TenantGenerationRegistry } from './TenantGenerationRegistry.js';

// Content-free: a tenant id is a content-free identifier, never customer data.
export class UnknownTenantError extends Error {
  constructor(readonly tenantId: string) {
    super(`no tenant context assigned for ${tenantId}`);
    this.name = 'UnknownTenantError';
  }
}

// Maps tenantId → its own TenantContext. There is no global keyring: crypto/storage callers
// resolve a context here and use only that context's key material, so no tenant can ever reach
// another's keyring (shared-tier design §2.2 point 1). Holds 0..N contexts: a pool boots empty
// and fills from its assignment manifest.
export class TenantRegistry {
  constructor(
    private readonly generationRegistry: TenantGenerationRegistry<TenantContext, unknown>,
  ) {}

  register(context: TenantContext): void {
    const entries = new Map(this.generationRegistry.entries());
    entries.set(context.tenantId, { context, snapshot: entries.get(context.tenantId)?.snapshot });
    this.generationRegistry.replaceGeneration(this.generationRegistry.generation(), entries);
  }

  // Returns the dropped context (or undefined) so the caller can zeroize its key material on a
  // reassignment teardown (§2.2 point 5) — the registry only unmaps; it never decides zeroing.
  remove(tenantId: string): TenantContext | undefined {
    const previous = this.generationRegistry.get(tenantId);
    if (!previous) return undefined;
    const entries = new Map(this.generationRegistry.entries());
    entries.delete(tenantId);
    this.generationRegistry.replaceGeneration(this.generationRegistry.generation(), entries);
    return previous.context;
  }

  has(tenantId: string): boolean {
    return this.generationRegistry.get(tenantId) !== undefined;
  }

  get(tenantId: string): TenantContext {
    const entry = this.generationRegistry.get(tenantId);
    if (!entry) throw new UnknownTenantError(tenantId);
    return entry.context;
  }

  all(): TenantContext[] {
    return [...this.generationRegistry.entries().values()].map((entry) => entry.context);
  }

  get size(): number {
    return this.generationRegistry.entries().size;
  }
}
