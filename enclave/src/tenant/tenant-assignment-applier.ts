import type { TenantAssignment } from '@folklore/contracts';
import type { TenantContext } from './tenant-context.js';
import type { TenantIdentity } from './tenant-context-factory.js';
import type { TenantRegistry } from './tenant-registry.js';
import type { QueueAssignment } from './queue-set-drainer.js';

export type BuildTenantContext = (identity: TenantIdentity) => Promise<TenantContext>;

// Called after a dropped tenant's context is zeroized so co-resident subsystems holding that org's
// key material outside the registry (e.g. the synthesis consumer's resident theme index + LLM-cache
// RAM front) can drop it too (§2.2 pt 5). Content-free (tenant id only); best-effort, never throws.
export type OnTenantTornDown = (tenantId: string) => void | Promise<void>;

// Rebuilds the live TenantRegistry to match a delivered assignment manifest (design §4.3/§5): builds
// a context for each newly assigned tenant, and tears down + ZEROES the key material of every dropped
// one (§2.2 point 5). Idempotent — re-applying the same set is a no-op. Also the source of truth for
// the drain set, so a queue is added/removed in lock-step with its tenant's context.
export class TenantAssignmentApplier {
  private readonly assigned = new Map<string, TenantAssignment>();
  private applying = false;

  constructor(
    private readonly registry: TenantRegistry,
    private readonly build: BuildTenantContext,
    private readonly onTornDown?: OnTenantTornDown,
  ) {}

  queueAssignments(): QueueAssignment[] {
    return [...this.assigned.values()].map((a) => ({
      tenantId: a.tenantId,
      queueUrl: a.queueUrl,
    }));
  }

  async apply(assignments: TenantAssignment[]): Promise<void> {
    // A refresh that overlaps an in-flight apply is dropped, not queued: apply is idempotent and the
    // manifest stays in Redis, so the next refresh reconverges — no torn half-rebuilt registry.
    if (this.applying) return;
    this.applying = true;
    try {
      const desired = new Map(assignments.map((a) => [a.tenantId, a] as const));
      await this.tearDownDropped(desired);
      await this.buildAdded(desired);
    } finally {
      this.applying = false;
    }
  }

  private async tearDownDropped(desired: Map<string, TenantAssignment>): Promise<void> {
    for (const tenantId of [...this.assigned.keys()]) {
      if (desired.has(tenantId)) continue;
      this.assigned.delete(tenantId);
      this.registry.remove(tenantId)?.zeroize();
      if (this.onTornDown) {
        try {
          await this.onTornDown(tenantId);
        } catch {
          // Best-effort hygiene — never let an eviction slip strand the rest of the rebuild (ADL #18).
          console.error('tenant teardown hook failed', { tenant_id: tenantId });
        }
      }
    }
  }

  private async buildAdded(desired: Map<string, TenantAssignment>): Promise<void> {
    for (const assignment of desired.values()) {
      // ponytail: presence-only idempotency — an already-assigned id is skipped, so ANY in-place edit
      // of a live tenant's fields (kmsKeyId/queueUrl/recoveryPubkey) is ignored, not just the CMK.
      // Safe today because a tenant's routing identifiers are immutable once assigned (reassignment
      // adds/removes whole tenants). If these ever become mutable, diff the stored assignment and
      // drop-then-add the changed tenant.
      if (this.assigned.has(assignment.tenantId)) continue;
      try {
        const context = await this.build({
          tenantId: assignment.tenantId,
          kmsKeyId: assignment.kmsKeyId,
          recoveryPubkey: assignment.recoveryPubkey,
        });
        this.registry.register(context);
        this.assigned.set(assignment.tenantId, assignment);
      } catch (err) {
        // One tenant's boot failure (KMS/S3) must not starve its co-tenants; the next refresh retries
        // it. Log the error NAME only, never the raw error, and the content-free id (ADL #18).
        console.error('tenant context build failed', {
          tenant_id: assignment.tenantId,
          error: err instanceof Error ? err.name : 'unknown',
        });
      }
    }
  }
}
