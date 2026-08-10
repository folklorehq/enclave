import type { Logger } from '@folklore/core';
import type {
  AssignmentApplyResult,
  SignedAssignmentManifest,
  TenantAssignment,
  VersionedTenantAssignment,
} from '@folklore/contracts';
import type { TenantContext } from './tenant-context.js';
import type { TenantIdentity } from './TenantContextFactory.js';
import type { TenantRegistry } from './tenant-registry.js';
import type { QueueAssignment } from './QueueSetDrainer.js';
import { toInitialStorageKeyVersion } from './tenant-assignments.js';
import {
  isVerifiedAssignmentManifest,
  type VerifiedAssignmentManifest,
} from './VerifiedAssignmentManifest.js';

export type BuildTenantContext = (identity: TenantIdentity) => Promise<TenantContext>;
const TENANT_TEARDOWN_TIMEOUT_MS = 10_000;

// Called for every replaced or dropped context before it is zeroized so co-resident subsystems can
// synchronously detach independently-held key material. Content-free: tenant id only.
export type OnTenantTornDown = (tenantId: string) => void | Promise<void>;

// Rebuilds the live TenantRegistry to match a delivered assignment manifest (design §4.3/§5): builds
// a context for each newly assigned tenant, and tears down + ZEROES the key material of every dropped
// one (§2.2 point 5). Idempotent — re-applying the same set is a no-op. Also the source of truth for
// the drain set, so a queue is added/removed in lock-step with its tenant's context.
export class TenantAssignmentApplier {
  private readonly assigned = new Map<string, VersionedTenantAssignment>();
  private applying = false;
  private lastAcceptedGeneration = 0;

  constructor(
    private readonly registry: TenantRegistry,
    private readonly build: BuildTenantContext,
    private readonly logger: Logger,
    private readonly onTornDown?: OnTenantTornDown,
    private readonly teardownTimeoutMs: number = TENANT_TEARDOWN_TIMEOUT_MS,
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
    if (!(await this.applyVersioned(manifest.assignments, true))) {
      throw new Error('assignment_manifest_apply_failed');
    }
    if (!this.matchesAssignments(manifest.assignments)) {
      throw new Error('assignment_manifest_apply_incomplete');
    }
    this.lastAcceptedGeneration = manifest.generation;
    return { applied: true, generation: manifest.generation };
  }

  async apply(assignments: TenantAssignment[]): Promise<boolean> {
    return this.applyVersioned(assignments.map(toInitialStorageKeyVersion), false);
  }

  private async applyVersioned(
    assignments: VersionedTenantAssignment[],
    hasSignedRecoveryEvidence: boolean,
  ): Promise<boolean> {
    // A refresh that overlaps an in-flight apply is dropped, not queued: apply is idempotent and the
    // manifest stays in Redis, so the next refresh reconverges — no torn half-rebuilt registry.
    if (this.applying) return false;
    this.applying = true;
    try {
      const desired = new Map(assignments.map((a) => [a.tenantId, a] as const));
      this.assertAssignmentTransitions(desired);
      const staged = await this.buildReplacements(desired, hasSignedRecoveryEvidence);
      if (!staged) return false;
      await this.commit(desired, staged);
      return true;
    } finally {
      this.applying = false;
    }
  }

  private async buildReplacements(
    desired: Map<string, VersionedTenantAssignment>,
    hasSignedRecoveryEvidence: boolean,
  ): Promise<Map<string, TenantContext> | null> {
    const staged = new Map<string, TenantContext>();
    for (const assignment of desired.values()) {
      const current = this.assigned.get(assignment.tenantId);
      if (current && this.assignmentsMatch(current, assignment)) continue;
      try {
        const context = await this.build({
          tenantId: assignment.tenantId,
          kmsKeyId: assignment.kmsKeyId,
          activeStorageKeyVersion: assignment.activeStorageKeyVersion,
          storageKeyHistory: assignment.storageKeyHistory,
          recoveryPubkey: assignment.recoveryPubkey,
          ...(hasSignedRecoveryEvidence ? { signedRecoveryPubkey: assignment.recoveryPubkey } : {}),
          sealedBlobBucket: assignment.sealedBlobBucket,
          rawPayloadsBucket: assignment.rawPayloadsBucket,
          processedBucket: assignment.processedBucket,
        });
        staged.set(assignment.tenantId, context);
      } catch (err) {
        // One tenant's boot failure (KMS/S3) must not starve its co-tenants; the next refresh retries
        // it. Log the error NAME only, never the raw error, and the content-free id.
        this.logger.error('tenant context build failed', {
          tenant_id: assignment.tenantId,
          error: err instanceof Error ? err.name : 'unknown',
        });
        for (const context of staged.values()) context.zeroize();
        return null;
      }
    }
    return staged;
  }

  private async commit(
    desired: Map<string, VersionedTenantAssignment>,
    staged: Map<string, TenantContext>,
  ): Promise<void> {
    const retired: Array<{ tenantId: string; context: TenantContext }> = [];
    for (const [tenantId, context] of staged) {
      if (this.registry.has(tenantId)) {
        retired.push({ tenantId, context: this.registry.get(tenantId) });
      }
      this.registry.register(context);
    }
    for (const tenantId of this.assigned.keys()) {
      if (desired.has(tenantId)) continue;
      const context = this.registry.remove(tenantId);
      if (context) retired.push({ tenantId, context });
    }
    this.assigned.clear();
    for (const [tenantId, assignment] of desired) this.assigned.set(tenantId, assignment);

    const teardownResults = await Promise.allSettled(
      retired.map(({ tenantId }) => this.runTornDown(tenantId)),
    );
    let didFail = false;
    for (const [index, result] of teardownResults.entries()) {
      if (result.status === 'fulfilled') continue;
      didFail = true;
      this.logger.error('tenant teardown hook failed', {
        tenant_id: retired[index]?.tenantId ?? 'unknown',
      });
    }
    for (const { tenantId, context } of retired) {
      try {
        context.zeroize();
      } catch {
        didFail = true;
        this.logger.error('tenant context zeroize failed', { tenant_id: tenantId });
      }
    }
    if (didFail) throw new Error('assignment_manifest_teardown_failed');
  }

  private async runTornDown(tenantId: string): Promise<void> {
    if (!this.onTornDown) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<void>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error('tenant_teardown_timeout')),
        this.teardownTimeoutMs,
      );
    });
    try {
      await Promise.race([this.onTornDown(tenantId), timedOut]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private assertAssignmentTransitions(assignments: Map<string, VersionedTenantAssignment>): void {
    for (const assignment of assignments.values()) {
      const current = this.assigned.get(assignment.tenantId);
      if (current) {
        if (!this.immutableAssignmentsMatch(current, assignment)) {
          throw new Error('assignment_manifest_assignment_changed');
        }
        this.assertStorageKeyTransition(current, assignment);
      }
      this.assertActiveStorageKey(assignment);
    }
  }

  private assertActiveStorageKey(assignment: VersionedTenantAssignment): void {
    const active = assignment.storageKeyHistory.at(-1);
    if (
      !active ||
      active.version !== assignment.activeStorageKeyVersion ||
      active.storageKeyId !== assignment.storageKeyId
    ) {
      throw new Error('assignment_storage_key_active_invalid');
    }
  }

  private assertStorageKeyTransition(
    current: VersionedTenantAssignment,
    next: VersionedTenantAssignment,
  ): void {
    if (next.storageKeyHistory.length < current.storageKeyHistory.length) {
      throw new Error('assignment_storage_key_history_dropped');
    }
    for (const [index, entry] of current.storageKeyHistory.entries()) {
      const retained = next.storageKeyHistory[index];
      if (
        !retained ||
        retained.version !== entry.version ||
        retained.storageKeyId !== entry.storageKeyId
      ) {
        throw new Error('assignment_storage_key_history_relabelled');
      }
    }
    if (next.activeStorageKeyVersion < current.activeStorageKeyVersion) {
      throw new Error('assignment_storage_key_rollback_rejected');
    }
  }

  private immutableAssignmentsMatch(
    left: VersionedTenantAssignment,
    right: VersionedTenantAssignment,
  ): boolean {
    return (
      left.tenantId === right.tenantId &&
      left.kmsKeyId === right.kmsKeyId &&
      left.queueUrl === right.queueUrl &&
      left.sealedBlobBucket === right.sealedBlobBucket &&
      left.rawPayloadsBucket === right.rawPayloadsBucket &&
      left.processedBucket === right.processedBucket &&
      left.recoveryPubkey === right.recoveryPubkey
    );
  }

  private matchesAssignments(assignments: VersionedTenantAssignment[]): boolean {
    if (this.assigned.size !== assignments.length) return false;
    return assignments.every((assignment) => {
      const current = this.assigned.get(assignment.tenantId);
      return current !== undefined && this.assignmentsMatch(current, assignment);
    });
  }

  private assignmentsMatch(
    left: VersionedTenantAssignment,
    right: VersionedTenantAssignment,
  ): boolean {
    return (
      left.tenantId === right.tenantId &&
      left.kmsKeyId === right.kmsKeyId &&
      left.storageKeyId === right.storageKeyId &&
      left.activeStorageKeyVersion === right.activeStorageKeyVersion &&
      JSON.stringify(left.storageKeyHistory) === JSON.stringify(right.storageKeyHistory) &&
      left.queueUrl === right.queueUrl &&
      left.sealedBlobBucket === right.sealedBlobBucket &&
      left.rawPayloadsBucket === right.rawPayloadsBucket &&
      left.processedBucket === right.processedBucket &&
      left.recoveryPubkey === right.recoveryPubkey
    );
  }
}
