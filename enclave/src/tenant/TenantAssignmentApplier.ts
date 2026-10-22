import type { Logger } from '@folklore/core';
import type {
  AssignmentApplyResult,
  NormalizedAssignmentManifestV1,
  RecoveryKeyBindingV1,
  SignedActivePolicyCarrierV1,
  TenantAssignment,
  VersionedTenantAssignment,
} from '@folklore/contracts';
import type { TenantContext } from './tenant-context.js';
import { HnswStore } from '../hnsw/index.js';
import type { ResidentIndexOffer, TenantIdentity } from './TenantContextFactory.js';
import { TenantRegistry } from './tenant-registry.js';
import type { QueueAssignment } from './QueueSetDrainer.js';
import { toInitialStorageKeyVersion } from './tenant-assignments.js';
import {
  TenantGenerationRegistry,
  type TenantGenerationEntry,
  type TenantGenerationPointer,
} from './TenantGenerationRegistry.js';
import {
  TenantPolicySnapshotRegistry,
  type TenantPolicySnapshotLike,
} from './TenantPolicySnapshotRegistry.js';
import {
  isVerifiedAssignmentManifest,
  type VerifiedAssignmentManifest,
} from './VerifiedAssignmentManifest.js';
import { PolicyGenerationQuiescence } from './quiescence/PolicyGenerationQuiescence.js';
import type { TenantEviction } from './quiescence/tenant-generation-quiescence.js';

export type BuildTenantContext = (
  identity: TenantIdentity,
  resident?: ResidentIndexOffer,
) => Promise<TenantContext>;
export type TenantPolicyAssignment = VersionedTenantAssignment & {
  readonly activePolicyCarrier?: SignedActivePolicyCarrierV1;
  readonly recoveryKeyBinding?: RecoveryKeyBindingV1;
};
export type SignedRecoveryKeyFor = (assignment: TenantPolicyAssignment) => string | undefined;
export const TENANT_TEARDOWN_TIMEOUT_MS = 10_000;
// Mirrors the control plane's tenant grant ceiling, which the enclave cannot import; the HNSW predecessor wait must outlast this many teardowns.
export const MAX_REPLACED_CONTEXTS_PER_GENERATION = 12;
// Covers a full queue sweep and a synthesis job's visibility window; requests stay admitted meanwhile.
export const GENERATION_WORK_TIMEOUT_MS = 120_000;
const ACTIVATION_SUPERSEDED = 'assignment_generation_activation_superseded';

// Called for every replaced or dropped context before it is zeroized so co-resident subsystems can
// synchronously detach independently-held key material. Content-free: tenant id only.
export type OnTenantTornDown = (tenantId: string) => void | Promise<void>;
export type OnTenantActivated = (tenantId: string) => void;
export type OnTenantGenerationCommitted = (tenantId: string) => void;
export type OnTenantQuiescenceFailure = (
  tenantId: string,
  phase: 'generation' | 'teardown',
) => void;

export class TenantTeardownHookError extends Error {
  constructor() {
    super('tenant_teardown_hook_failed');
    this.name = 'TenantTeardownHookError';
  }
}

export interface TenantPolicyAssignmentApplierOptions<TSnapshot extends TenantPolicySnapshotLike> {
  readonly registry: TenantRegistry;
  readonly generationRegistry: TenantGenerationRegistry<TenantContext, TSnapshot>;
  readonly snapshots: TenantPolicySnapshotRegistry<TSnapshot, TenantContext>;
  readonly build: BuildTenantContext;
  readonly verifyPolicy: (assignment: TenantPolicyAssignment) => Promise<TSnapshot>;
  readonly signedRecoveryKey?: SignedRecoveryKeyFor;
  readonly logger: Logger;
  readonly onTornDown?: OnTenantTornDown;
  readonly onActivated?: OnTenantActivated;
  readonly onGenerationChanged?: TenantEviction;
  readonly onGenerationWorkQuiescing?: TenantEviction;
  readonly onQuiescenceFailure?: OnTenantQuiescenceFailure;
}

type StagedEntry = TenantGenerationEntry<TenantContext, TenantPolicySnapshotLike>;

interface PublishProgress {
  published: boolean;
  teardownReported: boolean;
}

interface PublishedGeneration {
  readonly registry: TenantGenerationRegistry<TenantContext, TenantPolicySnapshotLike>;
  readonly previous: TenantGenerationPointer<TenantContext, TenantPolicySnapshotLike>;
  readonly nextState: ReadonlyMap<string, StagedEntry>;
  readonly assignments: readonly TenantPolicyAssignment[];
  readonly generation: number;
}

interface StageInputs {
  readonly previous: ReadonlyMap<string, StagedEntry>;
  readonly staged: Map<string, StagedEntry>;
  readonly built: Set<TenantContext>;
  readonly signedRecoveryKeys: ReadonlyMap<string, string>;
  readonly snapshots: ReadonlyMap<string, TenantPolicySnapshotLike>;
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
  private policyApplyInFlight = false;
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
  private readonly onGenerationChanged: TenantEviction | undefined;
  private readonly onGenerationCommitted: OnTenantGenerationCommitted | undefined;
  private readonly onQuiescenceFailure: OnTenantQuiescenceFailure | undefined;
  private readonly policyMode:
    | TenantPolicyAssignmentApplierOptions<TenantPolicySnapshotLike>
    | undefined;
  private readonly policyQuiescence: PolicyGenerationQuiescence | undefined;

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
    onGenerationChanged?: TenantEviction,
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
      this.policyQuiescence = undefined;
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
    this.onQuiescenceFailure = registryOrOptions.onQuiescenceFailure;
    this.policyMode = registryOrOptions;
    this.policyQuiescence = new PolicyGenerationQuiescence({
      quiesceWork: registryOrOptions.onGenerationWorkQuiescing,
      quiesceRequests: registryOrOptions.onGenerationChanged,
      workTimeoutMs: GENERATION_WORK_TIMEOUT_MS,
      requestTimeoutMs: TENANT_TEARDOWN_TIMEOUT_MS,
      logger: registryOrOptions.logger,
    });
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
      this.applyWithInFlightMark(assignments, generation, digest),
    );
    this.policyApplyTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async applyWithInFlightMark(
    assignments: readonly TenantPolicyAssignment[],
    generation: number,
    digest?: string,
  ) {
    this.policyApplyInFlight = true;
    try {
      return await this.applyPolicyAssignments(assignments, generation, digest);
    } finally {
      this.policyApplyInFlight = false;
    }
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
    const quiescence = this.policyQuiescence;
    if (!this.policyMode || !quiescence) throw new Error('tenant_policy_applier_mode_unavailable');
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
    if (generation < expectedGeneration) {
      throw new Error('assignment_manifest_generation_mismatch');
    }
    await quiescence.settleLate();
    const previous = this.policyMode.generationRegistry.read();
    const staged = new Map<string, StagedEntry>();
    const built = new Set<TenantContext>();
    const quiesced = new Set<string>();
    const progress: PublishProgress = { published: false, teardownReported: false };
    try {
      const signedRecoveryKeys = this.signedRecoveryKeysFor(
        assignments,
        this.policyMode.signedRecoveryKey,
      );
      const verifiedSnapshots = new Map<string, TenantPolicySnapshotLike>();
      for (const assignment of assignments) {
        verifiedSnapshots.set(assignment.tenantId, await this.policyMode.verifyPolicy(assignment));
      }
      const stagedSnapshots = this.policyMode.snapshots.stage(verifiedSnapshots);
      const previousTenantIds = [...previous.entries.keys()];
      const onLateQuiesced = (tenantId: string, attempt: number) =>
        this.queueLateReactivation(tenantId, previous.generation, attempt);
      const stage: StageInputs = {
        previous: previous.entries,
        staged,
        built,
        signedRecoveryKeys,
        snapshots: stagedSnapshots,
      };
      await this.stageBatch(
        assignments.filter(({ tenantId }) => !previous.entries.has(tenantId)),
        stage,
      );
      await quiescence.quiesceWork(previousTenantIds, quiesced, onLateQuiesced);
      await this.stageBatch(
        assignments.filter(({ tenantId }) => previous.entries.has(tenantId)),
        stage,
      );
      const nextState = this.inManifestOrder(assignments, staged);
      await quiescence.quiesceRequests(previousTenantIds, quiesced, onLateQuiesced);
      this.policyMode.generationRegistry.replaceGeneration(
        previous.generation,
        nextState,
        generation,
        digest,
      );
      progress.published = true;
      HnswStore.markPublished(assignments.map(({ tenantId }) => tenantId));
      this.activePolicyGeneration = undefined;
      this.assigned.clear();
      for (const assignment of assignments) this.assigned.set(assignment.tenantId, assignment);
      this.lastAcceptedGeneration = generation;
      this.lastAcceptedDigest = digest;
      const state = await this.settlePublished(
        {
          registry: this.policyMode.generationRegistry,
          previous,
          nextState,
          assignments,
          generation,
        },
        progress,
      );
      return { applied: true, generation, state };
    } catch (error) {
      if (!progress.published) {
        for (const context of built) context.zeroize();
        if (!this.keepsClosed(previous.generation)) {
          for (const tenantId of quiesced) this.onActivated?.(tenantId);
        }
      } else if (!progress.teardownReported) {
        for (const tenantId of this.policyMode.generationRegistry.read().entries.keys()) {
          this.onQuiescenceFailure?.(tenantId, 'teardown');
        }
      }
      throw error;
    }
  }

  // The post-read mismatch keeps precedence over a teardown failure, but neither stops the replaced contexts from being zeroized.
  private async settlePublished(published: PublishedGeneration, progress: PublishProgress) {
    const reread = published.registry.read();
    let mismatch: unknown;
    try {
      this.assertPublishedState(reread, published);
    } catch (error) {
      mismatch = error;
    }
    const teardownErrors = await this.tearDownReplaced(published, progress);
    if (mismatch !== undefined) throw mismatch;
    if (teardownErrors.length > 0) throw teardownErrors[0];
    return reread;
  }

  private assertPublishedState(
    reread: TenantGenerationPointer<TenantContext, TenantPolicySnapshotLike>,
    { nextState, assignments, generation }: PublishedGeneration,
  ): void {
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
  }

  // Reports per failed tenant, never by walking the published registry: a tenant dropped to an empty manifest is not in it.
  private async tearDownReplaced(
    published: PublishedGeneration,
    progress: PublishProgress,
  ): Promise<unknown[]> {
    const errors: unknown[] = [];
    const failedTenantIds: string[] = [];
    for (const { tenantId, context } of this.replacedContexts(published)) {
      await this.tearDownReplacedContext(tenantId, context, errors, failedTenantIds);
    }
    progress.teardownReported = failedTenantIds.length > 0;
    for (const tenantId of failedTenantIds) this.onQuiescenceFailure?.(tenantId, 'teardown');
    return errors;
  }

  private replacedContexts({
    registry,
    previous,
    nextState,
  }: PublishedGeneration): Array<{ tenantId: string; context: TenantContext }> {
    const live = new Set<TenantContext>();
    for (const { context } of nextState.values()) live.add(context);
    for (const { context } of registry.read().entries.values()) live.add(context);
    return [...previous.entries]
      .filter(([, entry]) => !live.has(entry.context))
      .map(([tenantId, entry]) => ({ tenantId, context: entry.context }));
  }

  // The policy path zeroizes at once rather than quarantining, because a replaced index must be freed for its successor's wait to end.
  private async tearDownReplacedContext(
    tenantId: string,
    context: TenantContext,
    errors: unknown[],
    failedTenantIds: string[],
  ): Promise<void> {
    const { completed } = await this.runTornDown(tenantId);
    if (!completed) {
      this.logger.error('tenant teardown hook failed', { tenant_id: tenantId });
      failedTenantIds.push(tenantId);
      errors.push(new TenantTeardownHookError());
    }
    try {
      context.zeroize();
    } catch (error) {
      errors.push(error);
      if (!failedTenantIds.includes(tenantId)) failedTenantIds.push(tenantId);
    }
  }

  private async stageBatch(
    batch: readonly TenantPolicyAssignment[],
    inputs: StageInputs,
  ): Promise<void> {
    for (const assignment of batch) {
      inputs.staged.set(assignment.tenantId, await this.buildStaged(assignment, inputs));
    }
  }

  private async buildStaged(
    assignment: TenantPolicyAssignment,
    { previous, built, signedRecoveryKeys, snapshots }: StageInputs,
  ): Promise<StagedEntry> {
    const signedRecoveryPubkey = signedRecoveryKeys.get(assignment.tenantId);
    const resident = previous.get(assignment.tenantId)?.context.residentFactsIndex();
    const identity: TenantIdentity = {
      tenantId: assignment.tenantId,
      deploymentId: assignment.deploymentId,
      ...(assignment.tenantDeploymentId
        ? { tenantDeploymentId: assignment.tenantDeploymentId }
        : {}),
      kmsKeyId: assignment.kmsKeyId,
      activeStorageKeyVersion: assignment.activeStorageKeyVersion,
      storageKeyHistory: assignment.storageKeyHistory,
      recoveryPubkey: assignment.recoveryPubkey,
      ...(signedRecoveryPubkey ? { signedRecoveryPubkey } : {}),
      sealedBlobBucket: assignment.sealedBlobBucket,
      rawPayloadsBucket: assignment.rawPayloadsBucket,
      processedBucket: assignment.processedBucket,
    };
    const context = await (resident === undefined
      ? this.build(identity)
      : this.build(identity, { factsIndex: resident }));
    built.add(context);
    const snapshot = snapshots.get(assignment.tenantId);
    if (!snapshot) throw new Error('tenant_policy_snapshot_missing');
    return { context, snapshot };
  }

  private inManifestOrder(
    assignments: readonly TenantPolicyAssignment[],
    staged: ReadonlyMap<string, StagedEntry>,
  ): Map<string, StagedEntry> {
    const ordered = new Map<string, StagedEntry>();
    for (const { tenantId } of assignments) {
      const entry = staged.get(tenantId);
      if (!entry) throw new Error('tenant_policy_staged_entry_missing');
      ordered.set(tenantId, entry);
    }
    return ordered;
  }

  // Tenants stay closed only on a generation this applier published and has not yet activated.
  private keepsClosed(generation: number): boolean {
    return this.lastAcceptedGeneration === generation && this.activePolicyGeneration !== generation;
  }

  // A tenant that finished quiescing after its apply was refused reopens only on the generation it left.
  private queueLateReactivation(tenantId: string, generation: number, attempt: number): void {
    this.policyApplyTail = this.policyApplyTail.then(() => {
      const live = this.policyMode?.generationRegistry;
      if (!live || live.generation() !== generation || this.keepsClosed(generation)) return;
      if (!live.get(tenantId) || this.policyQuiescence?.attemptOf(tenantId) !== attempt) return;
      try {
        this.onActivated?.(tenantId);
      } catch {
        this.logger.error('tenant generation reactivation failed', { tenant_id: tenantId });
      }
    });
  }

  // Runs before any policy check or build, so one bad binding refuses the generation untouched.
  private signedRecoveryKeysFor(
    assignments: readonly TenantPolicyAssignment[],
    signedRecoveryKey: SignedRecoveryKeyFor | undefined,
  ): ReadonlyMap<string, string> {
    const signedKeys = new Map<string, string>();
    if (!signedRecoveryKey) return signedKeys;
    for (const assignment of assignments) {
      const signed = signedRecoveryKey(assignment);
      if (signed) signedKeys.set(assignment.tenantId, signed);
    }
    return signedKeys;
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
    // A stalled refresh activating late would lift the holds a newer in-flight apply has taken.
    if (this.policyApplyInFlight) throw new Error(ACTIVATION_SUPERSEDED);
    this.activePolicyGeneration = generation;
    for (const tenantId of this.policyMode.generationRegistry.read().entries.keys()) {
      this.onActivated?.(tenantId);
    }
  }

  // A stalled refresh would otherwise read an apply still in flight as already applied and ack it.
  matchesCurrentManifest(manifest: NormalizedAssignmentManifestV1): boolean {
    if (this.policyApplyInFlight) return false;
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
    if (!(await this.applyVersioned(manifest.assignments, manifest.generation))) {
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
    );
  }

  private async applyVersioned(
    assignments: readonly VersionedTenantAssignment[],
    generation?: number,
  ): Promise<boolean> {
    // A refresh that overlaps an in-flight apply is dropped, not queued: apply is idempotent and the
    // manifest stays in Redis, so the next refresh reconverges — no torn half-rebuilt registry.
    if (this.applying) return false;
    this.applying = true;
    try {
      const desired = new Map(assignments.map((a) => [a.tenantId, a] as const));
      this.assertAssignmentTransitions(desired);
      const staged = await this.buildReplacements(desired);
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
