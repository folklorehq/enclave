import type {
  DurableGenerationHighWaterCheckpointV1,
  GenerationContextV1,
} from '@folklore/contracts';
import type {
  DurableGenerationHighWaterClientPort,
  InferenceModelRole,
  TrustedTimeAuthorityPort,
  TrustedTimeReadContext,
} from '@folklore/inference';
import type { Cache } from '@folklore/core';
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

const DEFAULT_REFRESH_TIMEOUT_MS = 5_000;

export type TenantPolicySnapshotProvider = () => VerifiedActivePolicySnapshotV1 | undefined;

export interface TenantPolicyFreshnessPort {
  readonly highWater: DurableGenerationHighWaterClientPort;
  readonly trustedTime: TrustedTimeAuthorityPort;
  readonly expectedContext: () => GenerationContextV1;
  readonly refreshIntervalMs: number;
  readonly refreshTimeoutMs?: number;
  readonly evict: () => void;
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
      | 'active_policy_tenant_mismatch'
      | 'active_policy_role_binding_mismatch'
      | 'active_policy_snapshot_refresh_failed'
      | 'active_policy_snapshot_expired',
  ) {
    super(code);
    this.name = 'TenantPolicyBoundInferenceError';
  }
}

export class TenantPolicyBoundInference implements SynthesisInference {
  private trustedDeadline = 0;
  private lastTrustedNow = 0;
  private readonly options: TenantPolicyBoundInferenceOptions;

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
  }

  async embed(text: string): Promise<number[]> {
    const { binding, snapshot } = await this.bindingFor('embed');
    const cache = this.operationCache;
    if (!cache) return (await this.backendFor(binding, snapshot)).embed(text);
    const key = this.cacheKey(binding, snapshot, 'embed', text);
    const hit = await this.operationCacheGet(key, binding.modelId, 'embed');
    if (hit !== null) return JSON.parse(hit) as number[];
    const output = await (await this.backendFor(binding, snapshot)).embed(text);
    await cache.set(key, JSON.stringify(output));
    return output;
  }

  async generate(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    const { binding, snapshot } = await this.bindingFor('generate');
    const cache = this.operationCache;
    if (!cache)
      return (await this.backendFor(binding, snapshot)).generate(
        prompt,
        systemPrompt,
        temperature,
        shouldCache,
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
    const output = await (
      await this.backendFor(binding, snapshot)
    ).generate(prompt, systemPrompt, resolvedTemperature, shouldCache);
    if ((shouldCache ?? (() => true))(output)) await this.options.operationCache?.set(key, output);
    return output;
  }

  async critique(
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    const { binding, snapshot } = await this.bindingFor('critique');
    const cache = this.operationCache;
    if (!cache)
      return (await this.backendFor(binding, snapshot)).critique(prompt, systemPrompt, shouldCache);
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
    const output = await (
      await this.backendFor(binding, snapshot)
    ).critique(prompt, systemPrompt, shouldCache);
    if ((shouldCache ?? (() => true))(output)) await this.options.operationCache?.set(key, output);
    return output;
  }

  async generateStructured(
    prompt: string,
    tool: ToolSpec,
    systemPrompt?: string,
  ): Promise<unknown> {
    const { binding, snapshot } = await this.bindingFor('judge');
    const structured = this.options.backendForVerifiedBinding
      ? (await this.backendFor(binding, snapshot)).generateStructured
      : this.options.structured;
    if (!structured) {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
    }
    return structured(prompt, tool, systemPrompt);
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
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_unavailable');
    }
    if (!snapshot) {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_unavailable');
    }
    try {
      assertVerifiedActivePolicySnapshotV1(snapshot);
    } catch {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_unavailable');
    }
    if (snapshot.orgId !== this.tenantId || snapshot.tenantId !== this.tenantId) {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_tenant_mismatch');
    }
    let binding: VerifiedActivePolicyRoleBindingV1;
    try {
      binding = this.roleBinding(snapshot, role);
    } catch (error: unknown) {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw error;
    }
    await this.ensureFresh(snapshot);
    try {
      if (!this.options.runtimeEvidence && this.options.requireRuntimeEvidence) {
        throw new Error('runtime_evidence_unavailable');
      }
      this.options.runtimeEvidence?.assertSnapshot(snapshot);
    } catch {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
    }
    if (!this.options.verifiedBindingForwarder && this.options.requireBindingForwarding) {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
    }
    try {
      await this.options.verifiedBindingForwarder?.(binding, snapshot);
      await this.options.onVerifiedBinding?.(binding, snapshot);
    } catch {
      this.evictAfterRefreshFailure(this.options.freshness ?? this.options.freshnessProvider?.());
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
    }
    return { binding, snapshot };
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

  private async ensureFresh(snapshot: VerifiedActivePolicySnapshotV1): Promise<void> {
    const freshness = this.options.freshness ?? this.options.freshnessProvider?.();
    if (!freshness) {
      if (this.options.requireFreshness) {
        throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
      }
      return;
    }
    this.assertFreshnessOptions(freshness);
    try {
      const context: TrustedTimeReadContext = {
        orgId: this.tenantId,
        deploymentId: snapshot.deploymentId,
      };
      const sample = await this.withTimeout(
        freshness.trustedTime.read(context),
        freshness.refreshTimeoutMs ?? DEFAULT_REFRESH_TIMEOUT_MS,
      );
      if (
        sample.orgId !== this.tenantId ||
        sample.deploymentId !== snapshot.deploymentId ||
        !Number.isSafeInteger(sample.trustedNow) ||
        sample.trustedNow < this.lastTrustedNow
      ) {
        throw new Error('active_policy_trusted_time_invalid');
      }
      this.lastTrustedNow = sample.trustedNow;
      if (sample.trustedNow >= snapshot.policy.lifetime.snapshotExpiresAt) {
        throw new TenantPolicyBoundInferenceError('active_policy_snapshot_expired');
      }
      if (sample.trustedNow < this.trustedDeadline) return;
      const expected = freshness.expectedContext();
      assertGenerationContext(snapshot.generationContext, expected);
      const checkpoint = await this.withTimeout(
        freshness.highWater.read(expected),
        freshness.refreshTimeoutMs ?? DEFAULT_REFRESH_TIMEOUT_MS,
      );
      assertCheckpointExact(checkpoint, expected, snapshot.durableCheckpoint);
      this.trustedDeadline = sample.trustedNow + freshness.refreshIntervalMs;
    } catch (error: unknown) {
      this.evictAfterRefreshFailure(freshness);
      if (error instanceof TenantPolicyBoundInferenceError) throw error;
      throw new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed');
    }
  }

  private evictAfterRefreshFailure(freshness: TenantPolicyFreshnessPort | undefined): void {
    freshness?.evict();
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

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timer = setTimeout(() => reject(new Error('active_policy_refresh_timeout')), timeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

const GENERATION_CONTEXT_FIELDS = [
  'orgId',
  'deploymentId',
  'policyDigest',
  'policyGeneration',
  'activationGeneration',
  'configurationGeneration',
  'keysetEpoch',
  'keysetDigest',
  'releaseId',
  'protectedSourceCommit',
  'eifDigest',
  'pcr0',
  'bootRootDigest',
] as const;

function assertGenerationContext(actual: GenerationContextV1, expected: GenerationContextV1): void {
  for (const field of GENERATION_CONTEXT_FIELDS) {
    if (actual[field] !== expected[field]) throw new Error('active_policy_generation_mismatch');
  }
}

function assertCheckpointExact(
  checkpoint: DurableGenerationHighWaterCheckpointV1,
  expected: GenerationContextV1,
  installed: DurableGenerationHighWaterCheckpointV1,
): void {
  assertGenerationContext(checkpoint, expected);
  assertGenerationContext(checkpoint, installed);
  if (
    checkpoint.signerKeyId !== installed.signerKeyId ||
    checkpoint.signerPurpose !== installed.signerPurpose
  ) {
    throw new Error('active_policy_signer_mismatch');
  }
}
