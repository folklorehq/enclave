import type { GenerationContextV1 } from '@folklore/contracts';
import type {
  InferenceModelRole,
  TrustedTimeAuthorityPort,
  TrustedTimeReadContext,
} from '@folklore/inference';
import type { Cache } from '@folklore/core';
import { ServiceUnavailableError } from '@folklore/errors';
import type { InferenceOperation, InferenceUsageSink } from '@folklore/inference';
import type { ToolSpec } from '@folklore/inference';
import {
  assertVerifiedActivePolicyRoleBindingV1,
  assertVerifiedActivePolicySnapshotV1,
  type VerifiedActivePolicyRoleBindingV1,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import { inferenceModel, inferenceModelRevision } from './phala.js';
import type { SynthesisInference } from './CachedInference.js';
import { llmCacheKey } from './llm-cache.js';
import { TrustedTimeAuthorityError } from './TrustedTimeAuthority.js';
import { tagInferenceRole } from '../tenant/message-failure/inference-role-tag.js';
import { TransientInferenceRetry, type TransientRetryWindows } from './TransientInferenceRetry.js';
import {
  transientRetryWindows,
  type InferenceLatencyProfile,
} from './public-aci-operation-limits.js';
import type { RecentGenerationHighWaterPort } from './ports.js';
import {
  RENEWAL_GRACE_READ_COUNT,
  assertGenerationContextEqual,
  servingCheckpointForInstalled,
} from './renewal-grace.js';

const DEFAULT_REFRESH_TIMEOUT_MS = 5_000;
const REFRESH_REASON_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const REFRESH_REASON_PREFIXES = [
  'active_policy_',
  'high_water_',
  'trusted_time_',
  'runtime_evidence_',
  'nsm_',
  'clock_raw_',
] as const;
const MAX_REFRESH_REASON_DEPTH = 8;
const REFRESH_READ_ATTEMPTS = 2;
const REFRESH_TIMEOUT_CODE = 'active_policy_refresh_timeout';
const HIGH_WATER_CODE_PREFIX = 'high_water_';
const HIGH_WATER_TRANSPORT_UNAVAILABLE = 'high_water_transport_unavailable';
export const RUNTIME_EVIDENCE_BACKEND_UNAVAILABLE = 'runtime_evidence_backend_unavailable';

export type TenantPolicySnapshotProvider = () => VerifiedActivePolicySnapshotV1 | undefined;

export interface TenantPolicyFreshnessPort {
  readonly highWater: RecentGenerationHighWaterPort;
  readonly trustedTime: TrustedTimeAuthorityPort;
  readonly expectedContext: () => GenerationContextV1;
  readonly refreshIntervalMs: number;
  readonly refreshTimeoutMs?: number;
  /** Withholds the snapshot the failed operation used, naming the refusal; a missing snapshot evicts nothing installed. */
  readonly evict: (snapshot?: VerifiedActivePolicySnapshotV1, code?: string) => void;
  /** Rises on every refusal of this tenant's snapshot by any caller; a deadline stamped earlier is void. */
  readonly refusalEpoch?: () => number;
  /** Lifts a withhold only for a full re-verification taken at the current epoch. */
  readonly confirm?: (snapshot: VerifiedActivePolicySnapshotV1, epoch: number) => void;
}

export interface TenantPolicyRuntimeEvidencePort {
  assertSnapshot(snapshot: VerifiedActivePolicySnapshotV1): void;
}

export type TenantPolicyVerifiedBindingForwarder = (
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
) => unknown;

export type TenantPolicyOperationBackend = SynthesisInference & {
  generateStructured?: (prompt: string, tool: ToolSpec, systemPrompt?: string) => Promise<unknown>;
};

export type TenantPolicyVerifiedBindingBackendFactory = (
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
) => Promise<TenantPolicyOperationBackend>;

/** Admits one tenant's upstream call, running it in the caller's own async context. */
export interface UpstreamCallGate {
  run<T>(tenantId: string, call: () => Promise<T>): Promise<T>;
}

export interface TenantPolicyBoundInferenceOptions {
  readonly operationCache?: Cache;
  readonly usageSink?: InferenceUsageSink;
  readonly freshness?: TenantPolicyFreshnessPort;
  readonly freshnessProvider?: () => TenantPolicyFreshnessPort | undefined;
  readonly requireFreshness?: boolean;
  readonly runtimeEvidence?: TenantPolicyRuntimeEvidencePort;
  readonly requireRuntimeEvidence?: boolean;
  readonly verifiedBindingForwarder?: TenantPolicyVerifiedBindingForwarder;
  readonly requireBindingForwarding?: boolean;
  readonly backendForVerifiedBinding?: TenantPolicyVerifiedBindingBackendFactory;
  readonly transientRetry?: TransientInferenceRetry;
  readonly latencyProfile?: InferenceLatencyProfile;
  readonly upstreamGate?: UpstreamCallGate;
  readonly structured?: (prompt: string, tool: ToolSpec, systemPrompt?: string) => Promise<unknown>;
  readonly onVerifiedBinding?: (
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
  ) => unknown;
}

export class TenantPolicyBoundInferenceError extends Error {
  constructor(
    readonly code:
      | 'active_policy_snapshot_unavailable'
      | 'active_policy_snapshot_unverified'
      | 'active_policy_tenant_mismatch'
      | 'active_policy_role_binding_mismatch'
      | 'active_policy_snapshot_refresh_failed'
      | 'active_policy_snapshot_expired',
    readonly reason?: string,
  ) {
    super(code);
    this.name = 'TenantPolicyBoundInferenceError';
  }
}

export class TenantPolicyBoundInference implements SynthesisInference {
  private trustedDeadline = 0;
  private deadlineSnapshot: VerifiedActivePolicySnapshotV1 | undefined;
  private deadlineEpoch: number | undefined;
  private lastTrustedNow = 0;
  private readonly options: TenantPolicyBoundInferenceOptions;
  private readonly transientRetry: TransientInferenceRetry;

  constructor(
    private readonly tenantId: string,
    private readonly snapshotProvider: TenantPolicySnapshotProvider,
    private readonly backend: SynthesisInference,
    optionsOrSink:
      | TenantPolicyBoundInferenceOptions
      | ((binding: VerifiedActivePolicyRoleBindingV1) => unknown) = {},
  ) {
    this.options =
      typeof optionsOrSink === 'function' ? { onVerifiedBinding: optionsOrSink } : optionsOrSink;
    this.assertFreshnessOptions(this.options.freshness);
    this.transientRetry = this.options.transientRetry ?? new TransientInferenceRetry();
  }

  async embed(text: string): Promise<number[]> {
    return this.underRole('embed', () => this.embedUnderPolicy(text));
  }

  async generate(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    return this.underRole('generate', () =>
      this.generateUnderPolicy(prompt, systemPrompt, temperature, shouldCache),
    );
  }

  async critique(
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    return this.underRole('critique', () =>
      this.critiqueUnderPolicy(prompt, systemPrompt, shouldCache),
    );
  }

  async generateStructured(
    prompt: string,
    tool: ToolSpec,
    systemPrompt?: string,
  ): Promise<unknown> {
    return this.underRole('judge', () => this.judgeUnderPolicy(prompt, tool, systemPrompt));
  }

  // The role is a closed policy name, so a failure code can say which provider call failed.
  // The gate wraps binding and the trusted-time read too, so a queued call never ages a checkpoint.
  private async underRole<T>(role: InferenceModelRole, operation: () => Promise<T>): Promise<T> {
    const gate = this.options.upstreamGate;
    try {
      return await (gate ? gate.run(this.tenantId, operation) : operation());
    } catch (error: unknown) {
      tagInferenceRole(error, role);
      throw error;
    }
  }

  private async embedUnderPolicy(text: string): Promise<number[]> {
    const { binding, snapshot } = await this.bindingFor('embed');
    const cache = this.operationCache;
    const embedOnce = () =>
      this.transientRetry.run(
        async () => (await this.backendFor(binding, snapshot)).embed(text),
        this.retryWindows('embed'),
      );
    if (!cache) return embedOnce();
    const key = this.cacheKey(binding, snapshot, 'embed', text);
    const hit = await this.operationCacheGet(key, binding.modelId, 'embed');
    if (hit !== null) return JSON.parse(hit) as number[];
    const output = await embedOnce();
    await cache.set(key, JSON.stringify(output));
    return output;
  }

  private async generateUnderPolicy(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    const { binding, snapshot } = await this.bindingFor('generate');
    const cache = this.operationCache;
    if (!cache)
      return this.transientRetry.run(
        async () =>
          (await this.backendFor(binding, snapshot)).generate(
            prompt,
            systemPrompt,
            temperature,
            shouldCache,
          ),
        this.retryWindows('generate'),
      );
    const resolvedTemperature = this.validateTemperature(snapshot, binding, temperature);
    const key = this.cacheKey(
      binding,
      snapshot,
      'generate',
      JSON.stringify({
        prompt,
        systemPrompt: systemPrompt ?? null,
        temperature: resolvedTemperature,
      }),
    );
    const hit = await this.operationCacheGet(key, binding.modelId, 'generate');
    if (hit !== null) return hit;
    const output = await this.transientRetry.run(
      async () =>
        (await this.backendFor(binding, snapshot)).generate(
          prompt,
          systemPrompt,
          resolvedTemperature,
          shouldCache,
        ),
      this.retryWindows('generate'),
    );
    if ((shouldCache ?? (() => true))(output)) await this.options.operationCache?.set(key, output);
    return output;
  }

  private async critiqueUnderPolicy(
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    const { binding, snapshot } = await this.bindingFor('critique');
    const cache = this.operationCache;
    if (!cache)
      return this.transientRetry.run(
        async () =>
          (await this.backendFor(binding, snapshot)).critique(prompt, systemPrompt, shouldCache),
        this.retryWindows('critique'),
      );
    const critiqueTemperature = snapshot.policy.roles.critique.capabilities.temperature;
    const key = this.cacheKey(
      binding,
      snapshot,
      'critique',
      JSON.stringify({
        prompt,
        systemPrompt: systemPrompt ?? null,
        temperature: critiqueTemperature,
      }),
    );
    const hit = await this.operationCacheGet(key, binding.modelId, 'generate');
    if (hit !== null) return hit;
    const output = await this.transientRetry.run(
      async () =>
        (await this.backendFor(binding, snapshot)).critique(prompt, systemPrompt, shouldCache),
      this.retryWindows('critique'),
    );
    if ((shouldCache ?? (() => true))(output)) await this.options.operationCache?.set(key, output);
    return output;
  }

  private async judgeUnderPolicy(
    prompt: string,
    tool: ToolSpec,
    systemPrompt?: string,
  ): Promise<unknown> {
    const { binding, snapshot } = await this.bindingFor('judge');
    return this.transientRetry.run(async () => {
      const structured = this.options.backendForVerifiedBinding
        ? (await this.backendFor(binding, snapshot)).generateStructured
        : this.options.structured;
      if (!structured) {
        throw this.refuse(
          snapshot,
          new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed'),
        );
      }
      return structured(prompt, tool, systemPrompt);
    }, this.retryWindows('judge'));
  }

  private retryWindows(role: InferenceModelRole): TransientRetryWindows {
    return transientRetryWindows(role, this.options.latencyProfile ?? 'batch');
  }

  async authorize(role: InferenceModelRole): Promise<void> {
    await this.bindingFor(role);
  }

  private async backendFor(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
  ): Promise<TenantPolicyOperationBackend> {
    return this.options.backendForVerifiedBinding
      ? this.options.backendForVerifiedBinding(binding, snapshot)
      : this.backend;
  }

  private cacheKey(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    operation: string,
    input: string,
  ): string {
    const namespace = JSON.stringify({
      tenantId: this.tenantId,
      deploymentId: snapshot.deploymentId,
      policyDigest: snapshot.policyDigest,
      policyGeneration: snapshot.policyGeneration,
      activationGeneration: snapshot.activationGeneration,
      role: binding.role,
      modelId: binding.modelId,
      modelRevision: binding.modelRevision,
      modelArtifactDigest: binding.modelArtifactDigest,
      routeIdentityDigest: binding.routeIdentityDigest,
      operation,
    });
    return llmCacheKey(binding.modelId, namespace, input);
  }

  private async operationCacheGet(
    key: string,
    model: string,
    operation: InferenceOperation,
  ): Promise<string | null> {
    const hit = await this.operationCache?.get<string>(key);
    if (hit !== null && hit !== undefined) {
      try {
        this.options.usageSink?.({
          model,
          operation,
          promptTokens: 0,
          completionTokens: 0,
          cached: true,
        });
      } catch {
        /* usage reporting must not break replay */
      }
      return hit;
    }
    return null;
  }

  private get operationCache(): Cache | undefined {
    return this.options.backendForVerifiedBinding ? this.options.operationCache : undefined;
  }

  private validateTemperature(
    snapshot: VerifiedActivePolicySnapshotV1,
    binding: VerifiedActivePolicyRoleBindingV1,
    requested: number | undefined,
  ): number {
    const allowed = snapshot.policy.roles[binding.role].capabilities.temperature;
    const resolved = requested === undefined ? allowed : requested;
    if (!Number.isFinite(resolved) || resolved !== allowed) {
      throw new TenantPolicyBoundInferenceError('active_policy_role_binding_mismatch');
    }
    return resolved;
  }

  private async bindingFor(role: InferenceModelRole): Promise<{
    binding: VerifiedActivePolicyRoleBindingV1;
    snapshot: VerifiedActivePolicySnapshotV1;
  }> {
    let snapshot: VerifiedActivePolicySnapshotV1 | undefined;
    try {
      snapshot = this.snapshotProvider();
    } catch {
      this.evictAfterRefreshFailure();
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_unavailable');
    }
    if (!snapshot) {
      this.evictAfterRefreshFailure();
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_unavailable');
    }
    try {
      assertVerifiedActivePolicySnapshotV1(snapshot);
    } catch {
      // Not the withheld code: a snapshot that fails its own brand check is the cause, not an echo.
      throw this.refuse(
        snapshot,
        new TenantPolicyBoundInferenceError('active_policy_snapshot_unverified'),
      );
    }
    if (snapshot.orgId !== this.tenantId || snapshot.tenantId !== this.tenantId) {
      throw this.refuse(
        snapshot,
        new TenantPolicyBoundInferenceError('active_policy_tenant_mismatch'),
      );
    }
    let binding: VerifiedActivePolicyRoleBindingV1;
    try {
      binding = this.roleBinding(snapshot, role);
    } catch (error: unknown) {
      throw this.refuse(snapshot, error);
    }
    const freshness = this.currentFreshness();
    const epoch = freshness?.refusalEpoch?.();
    const verifiedInFull = await this.ensureFresh(snapshot, freshness, epoch);
    try {
      if (!this.options.runtimeEvidence && this.options.requireRuntimeEvidence) {
        throw new Error('runtime_evidence_unavailable');
      }
      this.options.runtimeEvidence?.assertSnapshot(snapshot);
      if (this.options.requireRuntimeEvidence && !this.options.backendForVerifiedBinding) {
        throw new Error(RUNTIME_EVIDENCE_BACKEND_UNAVAILABLE);
      }
    } catch (error: unknown) {
      throw this.refuse(
        snapshot,
        new TenantPolicyBoundInferenceError(
          'active_policy_snapshot_refresh_failed',
          this.refreshFailureReason(error),
        ),
      );
    }
    if (!this.options.verifiedBindingForwarder && this.options.requireBindingForwarding) {
      throw this.refuse(
        snapshot,
        new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed'),
      );
    }
    try {
      await this.options.verifiedBindingForwarder?.(binding, snapshot);
      await this.options.onVerifiedBinding?.(binding, snapshot);
    } catch {
      throw this.refuse(
        snapshot,
        new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed'),
      );
    }
    if (verifiedInFull && epoch !== undefined) freshness?.confirm?.(snapshot, epoch);
    return { binding, snapshot };
  }

  private refuse(snapshot: VerifiedActivePolicySnapshotV1, error: unknown): unknown {
    this.evictAfterRefreshFailure(snapshot, this.currentFreshness(), this.refusalCode(error));
    return error;
  }

  private refusalCode(error: unknown): string | undefined {
    if (!(error instanceof TenantPolicyBoundInferenceError)) return undefined;
    return error.reason ?? error.code;
  }

  private roleBinding(
    snapshot: VerifiedActivePolicySnapshotV1,
    role: InferenceModelRole,
  ): VerifiedActivePolicyRoleBindingV1 {
    let binding: VerifiedActivePolicyRoleBindingV1;
    try {
      binding = snapshot.roleBindingFor(role);
      assertVerifiedActivePolicyRoleBindingV1(binding);
    } catch {
      throw new TenantPolicyBoundInferenceError('active_policy_role_binding_mismatch');
    }
    const policyRole = snapshot.policy.roles[role];
    if (
      binding.orgId !== this.tenantId ||
      binding.orgId !== snapshot.orgId ||
      binding.deploymentId !== snapshot.deploymentId ||
      binding.role !== role ||
      binding.modelId !== inferenceModel(role) ||
      binding.modelRevision !== inferenceModelRevision(role) ||
      !policyRole ||
      !DIGEST_PATTERN.test(binding.modelArtifactDigest) ||
      !DIGEST_PATTERN.test(binding.routeIdentityDigest) ||
      binding.modelArtifactDigest !== policyRole.modelArtifactDigest ||
      binding.routeIdentityDigest !== policyRole.routeIdentityDigest ||
      binding.policyDigest !== snapshot.policyDigest ||
      binding.policyGeneration !== snapshot.policyGeneration ||
      binding.activationGeneration !== snapshot.activationGeneration
    ) {
      throw new TenantPolicyBoundInferenceError('active_policy_role_binding_mismatch');
    }
    return binding;
  }

  // True only when this call itself re-read the durable high-water and found the snapshot serving.
  private async ensureFresh(
    snapshot: VerifiedActivePolicySnapshotV1,
    freshness: TenantPolicyFreshnessPort | undefined,
    epoch: number | undefined,
  ): Promise<boolean> {
    if (!freshness) {
      if (this.options.requireFreshness) {
        throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
      }
      return false;
    }
    this.assertFreshnessOptions(freshness);
    try {
      const context: TrustedTimeReadContext = {
        orgId: this.tenantId,
        deploymentId: snapshot.deploymentId,
      };
      const timeoutMs = freshness.refreshTimeoutMs ?? DEFAULT_REFRESH_TIMEOUT_MS;
      // Taken once before the first attempt and kept across retries; only overlapping reads are exempt.
      const floor = this.lastTrustedNow;
      const sample = await this.readWithRetry(
        () => freshness.trustedTime.read(context),
        timeoutMs,
        (error) => this.isRefreshTimeout(error),
      );
      if (
        sample.orgId !== this.tenantId ||
        sample.deploymentId !== snapshot.deploymentId ||
        !Number.isSafeInteger(sample.trustedNow) ||
        sample.trustedNow < floor
      ) {
        throw new Error('active_policy_trusted_time_invalid');
      }
      this.lastTrustedNow = Math.max(this.lastTrustedNow, sample.trustedNow);
      // A late, smaller sample must never make an expired snapshot or a passed deadline look live.
      const now = this.lastTrustedNow;
      if (now >= snapshot.policy.lifetime.snapshotExpiresAt) {
        throw new TenantPolicyBoundInferenceError('active_policy_snapshot_expired');
      }
      if (this.deadlineHolds(now, snapshot, epoch)) return false;
      const expected = freshness.expectedContext();
      assertGenerationContextEqual(snapshot.generationContext, expected);
      const recent = await this.readWithRetry(
        () => freshness.highWater.readRecent(expected, RENEWAL_GRACE_READ_COUNT),
        timeoutMs,
        (error) => this.isTransientHighWaterFailure(error),
      );
      servingCheckpointForInstalled(recent, expected, snapshot.durableCheckpoint);
      this.extendDeadline(now + freshness.refreshIntervalMs, snapshot, epoch);
      return true;
    } catch (error: unknown) {
      const refusal =
        error instanceof TenantPolicyBoundInferenceError
          ? error
          : new TenantPolicyBoundInferenceError(
              'active_policy_snapshot_refresh_failed',
              this.refreshFailureReason(error),
            );
      this.evictAfterRefreshFailure(snapshot, freshness, this.refusalCode(refusal));
      throw refusal;
    }
  }

  // Stops at the first error the enclave did not raise; host-shaped errors never name the reason.
  private refreshFailureReason(error: unknown): string | undefined {
    let reason: string | undefined;
    let current: unknown = error;
    for (
      let depth = 0;
      depth < MAX_REFRESH_REASON_DEPTH && this.isEnclaveFailureCode(current);
      depth += 1
    ) {
      reason = current.message;
      current = current.cause;
    }
    return reason;
  }

  private isEnclaveFailureCode(value: unknown): value is Error {
    return (
      value instanceof Error &&
      (Object.getPrototypeOf(value) === Error.prototype ||
        value instanceof ServiceUnavailableError ||
        value instanceof TrustedTimeAuthorityError) &&
      REFRESH_REASON_PATTERN.test(value.message) &&
      REFRESH_REASON_PREFIXES.some((prefix) => value.message.startsWith(prefix))
    );
  }

  // A deadline vouches only for the snapshot and refusal epoch its own full refresh saw.
  private deadlineHolds(
    trustedNow: number,
    snapshot: VerifiedActivePolicySnapshotV1,
    epoch: number | undefined,
  ): boolean {
    return (
      trustedNow < this.trustedDeadline &&
      this.deadlineSnapshot === snapshot &&
      this.deadlineEpoch === epoch
    );
  }

  // A slower, older refresh of the same snapshot and epoch must not shorten a newer deadline.
  private extendDeadline(
    deadline: number,
    snapshot: VerifiedActivePolicySnapshotV1,
    epoch: number | undefined,
  ): void {
    if (
      this.deadlineSnapshot === snapshot &&
      this.deadlineEpoch === epoch &&
      deadline <= this.trustedDeadline
    ) {
      return;
    }
    this.trustedDeadline = deadline;
    this.deadlineSnapshot = snapshot;
    this.deadlineEpoch = epoch;
  }

  private currentFreshness(): TenantPolicyFreshnessPort | undefined {
    return this.options.freshness ?? this.options.freshnessProvider?.();
  }

  private evictAfterRefreshFailure(
    snapshot?: VerifiedActivePolicySnapshotV1,
    freshness: TenantPolicyFreshnessPort | undefined = this.currentFreshness(),
    code?: string,
  ): void {
    freshness?.evict(snapshot, code);
    this.trustedDeadline = 0;
  }

  private assertFreshnessOptions(freshness: TenantPolicyFreshnessPort | undefined): void {
    if (!freshness) return;
    if (
      !Number.isSafeInteger(freshness.refreshIntervalMs) ||
      freshness.refreshIntervalMs <= 0 ||
      (freshness.refreshTimeoutMs !== undefined &&
        (!Number.isSafeInteger(freshness.refreshTimeoutMs) || freshness.refreshTimeoutMs <= 0))
    ) {
      throw new Error('active_policy_freshness_config_invalid');
    }
  }

  // Only failures thrown by the read are retried, and only those `retryable` names; checks on its result are not.
  private async readWithRetry<T>(
    read: () => Promise<T>,
    timeoutMs: number,
    retryable: (error: unknown) => boolean,
  ): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.withTimeout(read(), timeoutMs);
      } catch (error: unknown) {
        if (attempt >= REFRESH_READ_ATTEMPTS || !retryable(error)) throw error;
      }
    }
  }

  // The trusted-time authority closes itself when a sample fails, so only a timeout is worth retrying.
  private isRefreshTimeout(error: unknown): boolean {
    return error instanceof Error && error.message === REFRESH_TIMEOUT_CODE;
  }

  // A high-water verification refusal is a result check; a transport failure or timeout is not.
  private isTransientHighWaterFailure(error: unknown): boolean {
    if (this.isRefreshTimeout(error)) return true;
    if (!(error instanceof Error)) return true;
    if (error.message === HIGH_WATER_TRANSPORT_UNAVAILABLE) return true;
    return !error.message.startsWith(HIGH_WATER_CODE_PREFIX);
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timer = setTimeout(() => reject(new Error(REFRESH_TIMEOUT_CODE)), timeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
