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
// another's keyring (shared-tier design §2.2 point 1). Holds 1..N contexts — a dedicated box is
// simply the registry with one assigned tenant (design §6.1: dedicated is the default tier).
export class TenantRegistry {
  private readonly contexts = new Map<string, TenantContext>();

  constructor(
    private readonly generationRegistry?: TenantGenerationRegistry<TenantContext, unknown>,
  ) {}

  register(context: TenantContext): void {
    if (this.generationRegistry) {
      const entries = new Map(this.generationRegistry.entries());
      entries.set(context.tenantId, { context, snapshot: entries.get(context.tenantId)?.snapshot });
      this.generationRegistry.replaceGeneration(this.generationRegistry.generation(), entries);
      return;
    }
    this.contexts.set(context.tenantId, context);
  }

  // Returns the dropped context (or undefined) so the caller can zeroize its key material on a
  // reassignment teardown (§2.2 point 5) — the registry only unmaps; it never decides zeroing.
  remove(tenantId: string): TenantContext | undefined {
    if (this.generationRegistry) {
      const previous = this.generationRegistry.get(tenantId);
      if (!previous) return undefined;
      const entries = new Map(this.generationRegistry.entries());
      entries.delete(tenantId);
      this.generationRegistry.replaceGeneration(this.generationRegistry.generation(), entries);
      return previous.context;
    }
    const context = this.contexts.get(tenantId);
    this.contexts.delete(tenantId);
    return context;
  }

  has(tenantId: string): boolean {
    if (this.generationRegistry) return this.generationRegistry.get(tenantId) !== undefined;
    return this.contexts.has(tenantId);
  }

  get(tenantId: string): TenantContext {
    if (this.generationRegistry) {
      const entry = this.generationRegistry.get(tenantId);
      if (!entry) throw new UnknownTenantError(tenantId);
      return entry.context;
    }
    const context = this.contexts.get(tenantId);
    if (!context) throw new UnknownTenantError(tenantId);
    return context;
  }

  all(): TenantContext[] {
    if (this.generationRegistry) {
      return [...this.generationRegistry.entries().values()].map((entry) => entry.context);
    }
    return [...this.contexts.values()];
  }

  get size(): number {
    if (this.generationRegistry) return this.generationRegistry.entries().size;
    return this.contexts.size;
  }
}
