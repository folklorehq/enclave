import type { Logger } from '@folklore/core';
import type {
  AssignmentApplyResult,
  SignedAssignmentManifest,
  TenantAssignment,
} from '@folklore/contracts';
import type { TenantContext } from './tenant-context.js';
import type { TenantIdentity } from './TenantContextFactory.js';
import type { TenantRegistry } from './tenant-registry.js';
import type { QueueAssignment } from './QueueSetDrainer.js';
import {
  isVerifiedAssignmentManifest,
  type VerifiedAssignmentManifest,
} from './VerifiedAssignmentManifest.js';

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
  private lastAcceptedGeneration = 0;

  constructor(
    private readonly registry: TenantRegistry,
    private readonly build: BuildTenantContext,
    private readonly logger: Logger,
    private readonly onTornDown?: OnTenantTornDown,
  ) {}

  queueAssignments(): QueueAssignment[] {
    return [...this.assigned.values()].map((a) => ({
      tenantId: a.tenantId,
      queueUrl: a.queueUrl,
      rawPayloadsBucket: a.rawPayloadsBucket,
      processedBucket: a.processedBucket,
    }));
  }

  generation(): number {
    return this.lastAcceptedGeneration;
  }

  matchesCurrentManifest(manifest: SignedAssignmentManifest): boolean {
    return (
      manifest.generation === this.lastAcceptedGeneration &&
      this.matchesAssignments(manifest.assignments)
    );
  }

  async applyManifest(manifest: VerifiedAssignmentManifest): Promise<AssignmentApplyResult> {
    if (!isVerifiedAssignmentManifest(manifest)) {
      throw new Error('assignment_manifest_unverified');
    }
    if (manifest.generation <= this.lastAcceptedGeneration) {
      return { applied: false, reason: 'stale' };
    }
    this.assertExistingAssignmentsUnchanged(manifest.assignments);
    if (!(await this.applyAssignments(manifest.assignments, true))) {
      throw new Error('assignment_manifest_apply_failed');
    }
    if (!this.matchesAssignments(manifest.assignments)) {
      throw new Error('assignment_manifest_apply_incomplete');
    }
    this.lastAcceptedGeneration = manifest.generation;
    return { applied: true, generation: manifest.generation };
  }

  async apply(assignments: TenantAssignment[]): Promise<boolean> {
    return this.applyAssignments(assignments, false);
  }

  private async applyAssignments(
    assignments: TenantAssignment[],
    hasSignedRecoveryEvidence: boolean,
  ): Promise<boolean> {
    // A refresh that overlaps an in-flight apply is dropped, not queued: apply is idempotent and the
    // manifest stays in Redis, so the next refresh reconverges — no torn half-rebuilt registry.
    if (this.applying) return false;
    this.applying = true;
    try {
      const desired = new Map(assignments.map((a) => [a.tenantId, a] as const));
      await this.tearDownDropped(desired);
      return await this.buildAdded(desired, hasSignedRecoveryEvidence);
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
          // Best-effort hygiene — never let an eviction slip strand the rest of the rebuild.
          this.logger.error('tenant teardown hook failed', { tenant_id: tenantId });
        }
      }
    }
  }

  private async buildAdded(
    desired: Map<string, TenantAssignment>,
    hasSignedRecoveryEvidence: boolean,
  ): Promise<boolean> {
    let allBuilt = true;
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
          storageKeyId: assignment.storageKeyId,
          recoveryPubkey: assignment.recoveryPubkey,
          ...(hasSignedRecoveryEvidence ? { signedRecoveryPubkey: assignment.recoveryPubkey } : {}),
          sealedBlobBucket: assignment.sealedBlobBucket,
          rawPayloadsBucket: assignment.rawPayloadsBucket,
          processedBucket: assignment.processedBucket,
        });
        this.registry.register(context);
        this.assigned.set(assignment.tenantId, assignment);
      } catch (err) {
        // One tenant's boot failure (KMS/S3) must not starve its co-tenants; the next refresh retries
        // it. Log the error NAME only, never the raw error, and the content-free id.
        this.logger.error('tenant context build failed', {
          tenant_id: assignment.tenantId,
          error: err instanceof Error ? err.name : 'unknown',
        });
        allBuilt = false;
      }
    }
    return allBuilt;
  }

  private assertExistingAssignmentsUnchanged(assignments: TenantAssignment[]): void {
    for (const assignment of assignments) {
      const current = this.assigned.get(assignment.tenantId);
      if (current && !this.assignmentsMatch(current, assignment)) {
        throw new Error('assignment_manifest_assignment_changed');
      }
    }
  }

  private matchesAssignments(assignments: TenantAssignment[]): boolean {
    if (this.assigned.size !== assignments.length) return false;
    return assignments.every((assignment) => {
      const current = this.assigned.get(assignment.tenantId);
      return current !== undefined && this.assignmentsMatch(current, assignment);
    });
  }

  private assignmentsMatch(left: TenantAssignment, right: TenantAssignment): boolean {
    return (
      left.tenantId === right.tenantId &&
      left.kmsKeyId === right.kmsKeyId &&
      left.storageKeyId === right.storageKeyId &&
      left.queueUrl === right.queueUrl &&
      left.sealedBlobBucket === right.sealedBlobBucket &&
      left.rawPayloadsBucket === right.rawPayloadsBucket &&
      left.processedBucket === right.processedBucket &&
      left.recoveryPubkey === right.recoveryPubkey
    );
  }
}
