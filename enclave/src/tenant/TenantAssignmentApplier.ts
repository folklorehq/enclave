import type { Logger } from '@folklore/core';
import type {
  AssignmentApplyResult,
  NormalizedAssignmentManifestV1,
  SignedActivePolicyCarrierV1,
  TenantAssignment,
  VersionedTenantAssignment,
} from '@folklore/contracts';
import type { TenantContext } from './tenant-context.js';
import type { TenantIdentity } from './TenantContextFactory.js';
import { TenantRegistry } from './tenant-registry.js';
import type { QueueAssignment } from './QueueSetDrainer.js';
import { toInitialStorageKeyVersion } from './tenant-assignments.js';
import {
  TenantGenerationRegistry,
  type TenantGenerationEntry,
} from './TenantGenerationRegistry.js';
import {
  TenantPolicySnapshotRegistry,
  type TenantPolicySnapshotLike,
} from './TenantPolicySnapshotRegistry.js';
import {
  isVerifiedAssignmentManifest,
  type VerifiedAssignmentManifest,
} from './VerifiedAssignmentManifest.js';

export type BuildTenantContext = (identity: TenantIdentity) => Promise<TenantContext>;
export type TenantPolicyAssignment = VersionedTenantAssignment & {
  readonly activePolicyCarrier?: SignedActivePolicyCarrierV1;
};
const TENANT_TEARDOWN_TIMEOUT_MS = 10_000;

// Called for every replaced or dropped context before it is zeroized so co-resident subsystems can
// synchronously detach independently-held key material. Content-free: tenant id only.
export type OnTenantTornDown = (tenantId: string) => void | Promise<void>;
export type OnTenantActivated = (tenantId: string) => void;
export type OnTenantGenerationChanged = (tenantId: string) => void | Promise<void>;
export type OnTenantGenerationCommitted = (tenantId: string) => void;
export type OnTenantQuiescenceFailure = (
  tenantId: string,
  phase: 'generation' | 'teardown',
) => void;

export interface TenantPolicyAssignmentApplierOptions<TSnapshot extends TenantPolicySnapshotLike> {
  readonly registry: TenantRegistry;
  readonly generationRegistry: TenantGenerationRegistry<TenantContext, TSnapshot>;
  readonly snapshots: TenantPolicySnapshotRegistry<TSnapshot, TenantContext>;
  readonly build: BuildTenantContext;
  readonly verifyPolicy: (assignment: TenantPolicyAssignment) => Promise<TSnapshot>;
  readonly logger: Logger;
  readonly onTornDown?: OnTenantTornDown;
  readonly onActivated?: OnTenantActivated;
  readonly onGenerationChanged?: OnTenantGenerationChanged;
}

interface TeardownHookResult {
  completed: boolean;
  settled: Promise<void>;
}

// Rebuilds the live TenantRegistry to match a delivered assignment manifest (design §4.3/§5): builds
// a context for each newly assigned tenant, and tears down + ZEROES the key material of every dropped
// one (§2.2 point 5). Idempotent — re-applying the same set is a no-op. Also the source of truth for
// the drain set, so a queue is added/removed in lock-step with its tenant's context.
export class TenantAssignmentApplier {
  private readonly assigned = new Map<string, TenantPolicyAssignment>();
  private applying = false;
  private policyApplyTail: Promise<void> = Promise.resolve();
  private lastAcceptedGeneration = 0;
  private lastAcceptedDigest: string | undefined;
  private activePolicyGeneration: number | undefined;
  private readonly registry: TenantRegistry;
  private readonly build: BuildTenantContext;
  private readonly logger: Logger;
  private readonly onTornDown: OnTenantTornDown | undefined;
  private readonly teardownTimeoutMs: number;
  private readonly defaultDeploymentId: string;
  private readonly onActivated: OnTenantActivated | undefined;
  private readonly onGenerationChanged: OnTenantGenerationChanged | undefined;
  private readonly onGenerationCommitted: OnTenantGenerationCommitted | undefined;
  private readonly onQuiescenceFailure: OnTenantQuiescenceFailure | undefined;
  private readonly policyMode:
    | TenantPolicyAssignmentApplierOptions<TenantPolicySnapshotLike>
    | undefined;

  constructor(
    registryOrOptions:
      | TenantRegistry
      | TenantPolicyAssignmentApplierOptions<TenantPolicySnapshotLike>,
    build?: BuildTenantContext,
    logger?: Logger,
    onTornDown?: OnTenantTornDown,
    teardownTimeoutMs: number = TENANT_TEARDOWN_TIMEOUT_MS,
    defaultDeploymentId = '',
    onActivated?: OnTenantActivated,
    onGenerationChanged?: OnTenantGenerationChanged,
    onGenerationCommitted?: OnTenantGenerationCommitted,
    onQuiescenceFailure?: OnTenantQuiescenceFailure,
  ) {
    if (registryOrOptions instanceof TenantRegistry) {
      if (!build || !logger) throw new Error('tenant_assignment_applier_dependencies_required');
      this.registry = registryOrOptions;
      this.build = build;
      this.logger = logger;
      this.onTornDown = onTornDown;
      this.teardownTimeoutMs = teardownTimeoutMs;
      this.defaultDeploymentId = defaultDeploymentId;
      this.onActivated = onActivated;
      this.onGenerationChanged = onGenerationChanged;
      this.onGenerationCommitted = onGenerationCommitted;
      this.onQuiescenceFailure = onQuiescenceFailure;
      return;
    }
    this.registry = registryOrOptions.registry;
    this.build = registryOrOptions.build;
    this.logger = registryOrOptions.logger;
    this.onTornDown = registryOrOptions.onTornDown;
    this.teardownTimeoutMs = TENANT_TEARDOWN_TIMEOUT_MS;
    this.defaultDeploymentId = '';
    this.onActivated = registryOrOptions.onActivated;
    this.onGenerationChanged = registryOrOptions.onGenerationChanged;
    this.onGenerationCommitted = undefined;
    this.onQuiescenceFailure = undefined;
    this.policyMode = registryOrOptions;
  }

  async applyAssignments(
    assignments: readonly TenantPolicyAssignment[],
    generation: number,
    digest?: string,
  ): Promise<{
    readonly applied: boolean;
    readonly generation: number;
    readonly state: ReturnType<
      TenantGenerationRegistry<TenantContext, TenantPolicySnapshotLike>['read']
    >;
  }> {
    const result = this.policyApplyTail.then(() =>
      this.applyPolicyAssignments(assignments, generation, digest),
    );
    this.policyApplyTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async applyPolicyAssignments(
    assignments: readonly TenantPolicyAssignment[],
    generation: number,
    digest?: string,
  ): Promise<{
    readonly applied: boolean;
    readonly generation: number;
    readonly state: ReturnType<
      TenantGenerationRegistry<TenantContext, TenantPolicySnapshotLike>['read']
    >;
  }> {
    if (!this.policyMode) throw new Error('tenant_policy_applier_mode_unavailable');
    const expectedGeneration = this.policyMode.generationRegistry.generation();
    if (generation === expectedGeneration) {
      if (
        digest !== undefined &&
        digest === this.policyMode.generationRegistry.read().digest &&
        this.matchesAssignments(assignments)
      ) {
        return {
          applied: false,
          generation,
          state: this.policyMode.generationRegistry.read(),
        };
      }
      throw new Error('assignment_manifest_generation_conflict');
    }
    if (generation !== expectedGeneration + 1) {
      throw new Error('assignment_manifest_generation_mismatch');
    }
    const previous = this.policyMode.generationRegistry.read();
    const staged = new Map<
      string,
      TenantGenerationEntry<TenantContext, TenantPolicySnapshotLike>
    >();
    const built = new Set<TenantContext>();
    const quiesced = new Set<string>();
    let published = false;
    try {
      const verifiedSnapshots = new Map<string, TenantPolicySnapshotLike>();
      for (const assignment of assignments) {
        verifiedSnapshots.set(assignment.tenantId, await this.policyMode.verifyPolicy(assignment));
      }
      const stagedSnapshots = this.policyMode.snapshots.stage(verifiedSnapshots);
      for (const assignment of assignments) {
        const context = await this.build({
          tenantId: assignment.tenantId,
          deploymentId: assignment.deploymentId,
          ...(assignment.tenantDeploymentId
            ? { tenantDeploymentId: assignment.tenantDeploymentId }
            : {}),
          kmsKeyId: assignment.kmsKeyId,
          activeStorageKeyVersion: assignment.activeStorageKeyVersion,
          storageKeyHistory: assignment.storageKeyHistory,
          recoveryPubkey: assignment.recoveryPubkey,
          sealedBlobBucket: assignment.sealedBlobBucket,
          rawPayloadsBucket: assignment.rawPayloadsBucket,
          processedBucket: assignment.processedBucket,
        });
        built.add(context);
        const snapshot = stagedSnapshots.get(assignment.tenantId);
        if (!snapshot) throw new Error('tenant_policy_snapshot_missing');
        staged.set(assignment.tenantId, { context, snapshot });
      }
      const nextState = new Map(
        [...staged].map(([tenantId, entry]) => [
          tenantId,
          { context: entry.context, snapshot: entry.snapshot },
        ]),
      );
      for (const tenantId of previous.entries.keys()) {
        await this.policyMode.onGenerationChanged?.(tenantId);
        quiesced.add(tenantId);
      }
      this.policyMode.generationRegistry.replaceGeneration(
        previous.generation,
        nextState,
        generation,
        digest,
      );
      published = true;
      this.activePolicyGeneration = undefined;
      this.assigned.clear();
      for (const assignment of assignments) this.assigned.set(assignment.tenantId, assignment);
      this.lastAcceptedGeneration = generation;
      this.lastAcceptedDigest = digest;
      const reread = this.policyMode.generationRegistry.read();
      if (reread.generation !== generation || reread.entries.size !== assignments.length) {
        throw new Error('tenant_generation_post_read_mismatch');
      }
      for (const assignment of assignments) {
        const entry = reread.entries.get(assignment.tenantId);
        if (
          !entry ||
          entry.context !== nextState.get(assignment.tenantId)?.context ||
          entry.snapshot !== nextState.get(assignment.tenantId)?.snapshot
        ) {
          throw new Error('tenant_generation_post_read_mismatch');
        }
      }
      for (const [tenantId, oldEntry] of previous.entries) {
        if (
          !reread.entries.has(tenantId) ||
          reread.entries.get(tenantId)?.context !== oldEntry.context
        ) {
          try {
            await this.onTornDown?.(tenantId);
          } finally {
            oldEntry.context.zeroize();
          }
        }
      }
      return { applied: true, generation, state: reread };
    } catch (error) {
      if (!published) {
        for (const context of built) context.zeroize();
        for (const tenantId of quiesced) this.onActivated?.(tenantId);
      } else {
        for (const tenantId of this.policyMode.generationRegistry.read().entries.keys()) {
          this.onQuiescenceFailure?.(tenantId, 'teardown');
        }
      }
      throw error;
    }
  }

  queueAssignments(): QueueAssignment[] {
    if (this.policyMode && this.activePolicyGeneration !== this.lastAcceptedGeneration) return [];
    return [...this.assigned.values()]
      .filter((a) =>
        this.policyMode
          ? this.policyMode.generationRegistry.get(a.tenantId) !== undefined
          : this.registry.has(a.tenantId),
      )
      .map((a) => ({
        tenantId: a.tenantId,
        queueUrl: a.queueUrl,
        ...(this.lastAcceptedGeneration > 0
          ? { assignmentGeneration: this.lastAcceptedGeneration }
          : {}),
        rawPayloadsBucket: a.rawPayloadsBucket,
        processedBucket: a.processedBucket,
      }));
  }

  generation(): number {
    return this.lastAcceptedGeneration;
  }

  activateGeneration(generation: number): void {
    if (!this.policyMode || generation !== this.lastAcceptedGeneration) {
      throw new Error('assignment_generation_activation_mismatch');
    }
    if (this.activePolicyGeneration === generation) return;
    this.activePolicyGeneration = generation;
    for (const tenantId of this.policyMode.generationRegistry.read().entries.keys()) {
      this.onActivated?.(tenantId);
    }
  }

  matchesCurrentManifest(manifest: NormalizedAssignmentManifestV1): boolean {
    return (
      manifest.generation === this.lastAcceptedGeneration &&
      manifest.digest === this.lastAcceptedDigest &&
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
    if (!(await this.applyVersioned(manifest.assignments, true, manifest.generation))) {
      throw new Error('assignment_manifest_apply_failed');
    }
    if (!this.matchesAssignments(manifest.assignments)) {
      throw new Error('assignment_manifest_apply_incomplete');
    }
    this.lastAcceptedDigest = manifest.digest;
    return { applied: true, generation: manifest.generation };
  }

  async apply(assignments: TenantAssignment[]): Promise<boolean> {
    return this.applyVersioned(
      assignments.map((assignment) =>
        toInitialStorageKeyVersion(assignment, this.defaultDeploymentId),
      ),
      false,
    );
  }

  private async applyVersioned(
    assignments: readonly VersionedTenantAssignment[],
    hasSignedRecoveryEvidence: boolean,
    generation?: number,
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
      try {
        await this.commit(desired, staged, generation);
      } catch (error) {
        this.zeroizeStaged(staged);
        throw error;
      }
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
      if (
        current &&
        this.registry.has(assignment.tenantId) &&
        this.assignmentsMatch(current, assignment)
      )
        continue;
      try {
        const context = await this.build({
          tenantId: assignment.tenantId,
          deploymentId: assignment.deploymentId,
          ...(assignment.tenantDeploymentId
            ? { tenantDeploymentId: assignment.tenantDeploymentId }
            : {}),
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
    generation?: number,
  ): Promise<void> {
    const generationChanged = this.generationChangedTenants(desired, staged, generation);
    await this.quiesceGenerationChanged(generationChanged);
    const retired = this.retiredContexts(desired, staged);
    await this.teardownRetired(retired);

    for (const context of staged.values()) {
      this.registry.register(context);
    }
    for (const tenantId of this.assigned.keys()) {
      if (desired.has(tenantId)) continue;
      this.registry.remove(tenantId);
    }
    this.assigned.clear();
    for (const [tenantId, assignment] of desired) this.assigned.set(tenantId, assignment);
    if (generation !== undefined) this.lastAcceptedGeneration = generation;
    for (const tenantId of staged.keys()) this.onActivated?.(tenantId);
    for (const tenantId of generationChanged) this.onGenerationCommitted?.(tenantId);
  }

  private generationChangedTenants(
    desired: Map<string, VersionedTenantAssignment>,
    staged: Map<string, TenantContext>,
    generation?: number,
  ): string[] {
    if (generation === undefined || generation <= this.lastAcceptedGeneration) return [];
    return [...this.assigned.entries()]
      .filter(([tenantId, current]) => {
        const next = desired.get(tenantId);
        return next !== undefined && !staged.has(tenantId) && this.assignmentsMatch(current, next);
      })
      .map(([tenantId]) => tenantId);
  }

  private async quiesceGenerationChanged(tenantIds: string[]): Promise<void> {
    if (!this.onGenerationChanged || tenantIds.length === 0) return;
    const results = await Promise.allSettled(
      tenantIds.map((tenantId) => this.runGenerationChanged(tenantId)),
    );
    if (results.some((result) => result.status === 'rejected' || !result.value.completed)) {
      for (const [index, result] of results.entries()) {
        if (result.status === 'fulfilled' && result.value.completed) continue;
        this.onQuiescenceFailure?.(tenantIds[index]!, 'generation');
      }
      throw new Error('assignment_manifest_generation_quiesce_failed');
    }
  }

  private retiredContexts(
    desired: Map<string, VersionedTenantAssignment>,
    staged: Map<string, TenantContext>,
  ): Array<{ tenantId: string; context: TenantContext }> {
    const retired: Array<{ tenantId: string; context: TenantContext }> = [];
    for (const tenantId of staged.keys()) {
      if (this.registry.has(tenantId))
        retired.push({ tenantId, context: this.registry.get(tenantId) });
    }
    for (const tenantId of this.assigned.keys()) {
      if (desired.has(tenantId)) continue;
      if (!this.registry.has(tenantId)) continue;
      const context = this.registry.get(tenantId);
      retired.push({ tenantId, context });
    }
    return retired;
  }

  private async teardownRetired(
    retired: Array<{ tenantId: string; context: TenantContext }>,
  ): Promise<void> {
    const teardownResults = await Promise.allSettled(
      retired.map(({ tenantId }) => this.runTornDown(tenantId)),
    );
    let didFail = false;
    for (const [index, result] of teardownResults.entries()) {
      if (result.status === 'fulfilled' && result.value.completed) continue;
      didFail = true;
      this.logger.error('tenant teardown hook failed', {
        tenant_id: retired[index]?.tenantId ?? 'unknown',
      });
    }
    if (didFail) {
      this.quarantineRetired(
        retired,
        teardownResults.map((result) =>
          result.status === 'fulfilled'
            ? result.value
            : { completed: false, settled: Promise.resolve() },
        ),
      );
      for (const [index, result] of teardownResults.entries()) {
        if (result.status === 'fulfilled' && result.value.completed) continue;
        this.onQuiescenceFailure?.(retired[index]?.tenantId ?? 'unknown', 'teardown');
      }
      throw new Error('assignment_manifest_teardown_failed');
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

  private quarantineRetired(
    retired: Array<{ tenantId: string; context: TenantContext }>,
    teardownResults: TeardownHookResult[],
  ): void {
    for (const [{ tenantId, context }, result] of retired.map(
      (retiredContext, index) =>
        [
          retiredContext,
          teardownResults[index] ?? { completed: true, settled: Promise.resolve() },
        ] as const,
    )) {
      this.registry.remove(tenantId);
      void result.settled.then(() => {
        try {
          context.zeroize();
        } catch {
          this.logger.error('tenant context quarantine zeroize failed', { tenant_id: tenantId });
        }
      });
    }
  }

  private zeroizeStaged(staged: Map<string, TenantContext>): void {
    for (const [tenantId, context] of staged) {
      try {
        context.zeroize();
      } catch {
        this.logger.error('staged tenant context zeroize failed', { tenant_id: tenantId });
      }
    }
  }

  private async runTornDown(tenantId: string): Promise<TeardownHookResult> {
    if (!this.onTornDown) return { completed: true, settled: Promise.resolve() };
    const outcome = Promise.resolve()
      .then(() => this.onTornDown!(tenantId))
      .then(
        () => true,
        () => false,
      );
    const settled = outcome.then(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), this.teardownTimeoutMs);
    });
    try {
      const finished = await Promise.race([outcome, timeout]);
      return { completed: finished, settled };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async runGenerationChanged(tenantId: string): Promise<TeardownHookResult> {
    if (!this.onGenerationChanged) return { completed: true, settled: Promise.resolve() };
    const outcome = Promise.resolve()
      .then(() => this.onGenerationChanged!(tenantId))
      .then(
        () => true,
        () => false,
      );
    const settled = outcome.then(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), this.teardownTimeoutMs);
    });
    try {
      const finished = await Promise.race([outcome, timeout]);
      return { completed: finished, settled };
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

  private matchesAssignments(assignments: readonly VersionedTenantAssignment[]): boolean {
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
      left.deploymentId === right.deploymentId &&
      left.tenantDeploymentId === right.tenantDeploymentId &&
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
