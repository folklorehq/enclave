import type { GenerationContextV1 } from '@folklore/contracts';
import type {
  InferenceModelRole,
  TrustedTimeAuthorityPort,
  TrustedTimeReadContext,
  TrustedTimeSample,
} from '@folklore/inference';
import type { Logger } from '@folklore/core';
import { ServiceUnavailableError } from '@folklore/errors';
import { ProviderRouteError } from '@folklore/inference';
import {
  inferenceOutageScope,
  type InferenceOutageRecord,
} from './routing/inference-outage-scope.js';
import type {
  InferenceCallLabel,
  InferenceCallPhase,
  InferenceOperation,
  InferenceTimer,
  InferenceUsageSink,
} from '@folklore/inference';
import type { ToolSpec } from '@folklore/inference';
import {
  INFERENCE_OPERATION_BY_ROLE,
  assertVerifiedActivePolicyRoleBindingV1,
  assertVerifiedActivePolicySnapshotV1,
  type VerifiedActivePolicyRoleBindingV1,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import { inferenceModel, inferenceModelRevision } from './phala.js';
import { inferencePurposeScope } from './InferencePurposeScope.js';
import { float32Vector, type LlmOperationCache } from './vector-cache.js';
import {
  ACI_ROUTE,
  type InferenceRoute,
  type InferenceRouteResolver,
} from './routing/InferenceRouteResolver.js';
import { PROVIDER_ROUTE_POLICY } from './routing/provider-route-policy.js';
import {
  OPENAI_EMBED_CACHE_LABEL,
  type EmbeddingProvider,
} from './openai/OpenAIEmbedRouteComposition.js';
import { OPENAI_TRANSIENT_STATUSES, OpenAIEmbedRouteError } from './openai/openai-embed-errors.js';
import { OPENAI_EMBED_DIMENSIONS, OPENAI_EMBED_MODEL } from './openai/openai-embed-route-state.js';
import { ACTIVE_EMBEDDING_SPACE_IS_LEGACY } from './embedding-space.js';
import type { SynthesisInference } from './CachedInference.js';
import { ChunkQueue, ChunkQueueError } from './ChunkQueue.js';
import {
  GenerationStreamInterruptedError,
  assertStreamLive,
  cacheWhileLive,
  type GenerateStreamRequest,
  type StreamingInference,
} from './generate-stream.js';
import { llmCacheKey } from './llm-cache.js';
import { TrustedTimeAuthorityError } from './TrustedTimeAuthority.js';
import { DEFAULT_REFRESH_TIMEOUT_MS } from './attestation-turn-base.js';
import { attestationTurnScope } from './AttestationTurnScope.js';
import { tagInferenceRole } from '../tenant/message-failure/inference-role-tag.js';
import {
  TransientInferenceRetry,
  type BackoffObserver,
  type TransientRetryWindows,
} from './TransientInferenceRetry.js';
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
const STREAM_EMPTY_CODE = 'stream_empty';
const STREAM_FAILED_CODE = 'stream_failed';
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
  generateStream?: (
    prompt: string,
    systemPrompt: string | undefined,
    signal: AbortSignal,
  ) => AsyncIterable<string>;
};

export type TenantPolicyVerifiedBindingBackendFactory = (
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
  route?: InferenceRoute,
) => Promise<TenantPolicyOperationBackend>;

export interface UpstreamCallAdmission {
  /** One window per upstream: the role's configured model id. */
  readonly upstream: string;
  /** Wraps only a real wait, so an immediate admission records no span. */
  readonly onWait?: (wait: () => Promise<void>) => Promise<void>;
}

/** Admits one tenant's upstream call, running it in the caller's own async context. */
export interface UpstreamCallGate {
  run<T>(tenantId: string, call: () => Promise<T>, admission?: UpstreamCallAdmission): Promise<T>;
}

export interface TenantPolicyBoundInferenceOptions {
  readonly operationCache?: LlmOperationCache;
  readonly usageSink?: InferenceUsageSink;
  readonly timer?: InferenceTimer;
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
  readonly upstreamKeyFor?: (role: InferenceModelRole) => string | undefined;
  readonly upstreamKeyForRoute?: (route: InferenceRoute) => string | undefined;
  readonly logger?: Logger;
  readonly routeResolver?: InferenceRouteResolver;
  readonly embeddingProvider?: EmbeddingProvider;
  readonly structured?: (prompt: string, tool: ToolSpec, systemPrompt?: string) => Promise<unknown>;
  readonly onVerifiedBinding?: (
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
  ) => unknown;
}

type StreamOpening =
  | { readonly whole: string }
  | { readonly first: string; readonly rest: AsyncIterator<string> };

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

export class TenantPolicyBoundInference implements SynthesisInference, StreamingInference {
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
    return this.underRole(
      'generate',
      () => this.generateUnderPolicy(prompt, systemPrompt, temperature, shouldCache),
      false,
    );
  }

  generateStream(request: GenerateStreamRequest): AsyncIterable<string> {
    const abort = new AbortController();
    const queue = new ChunkQueue<string>(() => abort.abort());
    const bound = { ...request, signal: AbortSignal.any([request.signal, abort.signal]) };
    const producer = this.underRole('generate', () => this.streamUnderPolicy(bound, queue), false);
    void producer.then(
      () => queue.end(),
      (error: unknown) => queue.fail(error),
    );
    return queue;
  }

  async critique(
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    return this.underRole(
      'critique',
      () => this.critiqueUnderPolicy(prompt, systemPrompt, shouldCache),
      false,
    );
  }

  async generateStructured(
    prompt: string,
    tool: ToolSpec,
    systemPrompt?: string,
  ): Promise<unknown> {
    return this.underRole('judge', () => this.judgeUnderPolicy(prompt, tool, systemPrompt), false);
  }

  // The role is a closed policy name, so a failure code can say which provider call failed.
  // The gate wraps binding and the trusted-time read too, so a queued call never ages a checkpoint.
  private async underRole<T>(
    role: InferenceModelRole,
    operation: () => Promise<T>,
    gated = true,
  ): Promise<T> {
    try {
      return await (gated ? this.admitted(role, undefined, operation) : operation());
    } catch (error: unknown) {
      tagInferenceRole(error, role);
      throw error;
    }
  }

  // A fallback-capable role admits each attempt under its own route's window, never the primary's.
  private admitted<T>(
    role: InferenceModelRole,
    route: InferenceRoute | undefined,
    operation: () => Promise<T>,
  ): Promise<T> {
    const gate = this.options.upstreamGate;
    if (!gate) return operation();
    return gate.run(this.tenantId, operation, {
      upstream: this.upstreamOf(role, route),
      onWait: (wait) => this.timed('gate_wait', role, wait, route),
    });
  }

  // An unconfigured role has no model to key a window by; its refusal is the binding's to raise.
  private upstreamOf(role: InferenceModelRole, route?: InferenceRoute): string {
    if (role === 'embed' && !this.isLegacyEmbeddingSpace()) return OPENAI_EMBED_CACHE_LABEL;
    const keyed =
      route?.kind === 'provider' && this.options.upstreamKeyForRoute
        ? this.options.upstreamKeyForRoute(route)
        : this.options.upstreamKeyFor?.(role);
    if (keyed !== undefined) return keyed;
    try {
      return inferenceModel(role);
    } catch {
      return `role:${role}`;
    }
  }

  private async embedUnderPolicy(text: string): Promise<number[]> {
    if (!this.isLegacyEmbeddingSpace()) return this.embedOnProvider(text);
    const { binding, snapshot } = await this.bindingFor('embed');
    const cache = this.operationCache;
    const embedOnce = () =>
      this.runTransient('embed', ACI_ROUTE, async () =>
        (await this.backendFor(binding, snapshot, ACI_ROUTE)).embed(text),
      );
    if (!cache) return embedOnce();
    const key = this.cacheKey(binding, snapshot, 'embed', text, ACI_ROUTE);
    const hit = await this.replayVectorFrom(cache, key, binding.modelId);
    if (hit !== null) return hit;
    const output = float32Vector(await embedOnce());
    await cache.setVector(key, output);
    return output;
  }

  // Once the OpenAI route is compiled in, embedding never reads the Phala policy snapshot or falls back to it.
  private isLegacyEmbeddingSpace(): boolean {
    return ACTIVE_EMBEDDING_SPACE_IS_LEGACY;
  }

  private async embedOnProvider(text: string): Promise<number[]> {
    const provider = this.options.embeddingProvider;
    if (provider === undefined) throw new OpenAIEmbedRouteError('embedding_provider_absent');
    const embedOnce = () =>
      this.runTransient('embed', ACI_ROUTE, () => provider.embed(text), OPENAI_TRANSIENT_STATUSES);
    const cache = this.options.operationCache;
    if (!cache) return embedOnce();
    const key = this.providerEmbedCacheKey(provider, text);
    const hit = await this.replayVectorFrom(
      cache,
      key,
      OPENAI_EMBED_MODEL,
      TenantPolicyBoundInference.isCachedVector,
    );
    if (hit !== null) return hit;
    const output = float32Vector(await embedOnce());
    await cache.setVector(key, output);
    return output;
  }

  private static isCachedVector(hit: readonly number[]): boolean {
    return hit.length === OPENAI_EMBED_DIMENSIONS;
  }

  private providerEmbedCacheKey(provider: EmbeddingProvider, text: string): string {
    const namespace = JSON.stringify({
      tenantId: this.tenantId,
      op: 'embed',
      route: provider.cacheLabel,
    });
    return llmCacheKey(provider.cacheLabel, namespace, text);
  }

  private async generateUnderPolicy(
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    return this.withFallback(this.routeChainFor('generate'), (route) =>
      this.admitted('generate', route, async () => {
        const { binding, snapshot } = await this.bindingFor('generate');
        return this.generateOnRoute(
          binding,
          snapshot,
          route,
          prompt,
          systemPrompt,
          temperature,
          shouldCache,
        );
      }),
    );
  }

  private async generateOnRoute(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
    prompt: string,
    systemPrompt?: string,
    temperature?: number,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    const cache = this.operationCache;
    const generateOnce = (resolvedTemperature: number | undefined) =>
      this.runTransient('generate', route, async () =>
        (await this.backendFor(binding, snapshot, route)).generate(
          prompt,
          systemPrompt,
          resolvedTemperature,
          shouldCache,
        ),
      );
    if (!cache) return generateOnce(temperature);
    const resolvedTemperature =
      route.kind === 'provider'
        ? undefined
        : this.validateTemperature(snapshot, binding, temperature);
    const key = this.generateCacheKey(
      binding,
      snapshot,
      route,
      prompt,
      systemPrompt,
      resolvedTemperature,
    );
    const hit = await this.operationCacheGet(key, this.modelOf(binding, route), 'generate');
    if (hit !== null) return hit;
    const output = await generateOnce(resolvedTemperature);
    if ((shouldCache ?? (() => true))(output)) await this.options.operationCache?.set(key, output);
    return output;
  }

  private generateCacheKey(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
    prompt: string,
    systemPrompt: string | undefined,
    resolvedTemperature: number | undefined,
  ): string {
    return this.cacheKey(
      binding,
      snapshot,
      'generate',
      JSON.stringify({
        prompt,
        systemPrompt: systemPrompt ?? null,
        temperature: resolvedTemperature ?? null,
      }),
      route,
    );
  }

  private streamUnderPolicy(
    request: GenerateStreamRequest,
    queue: ChunkQueue<string>,
  ): Promise<void> {
    return this.withFallback(this.routeChainFor('generate'), (route) =>
      this.admitted('generate', route, async () => {
        const { binding, snapshot } = await this.bindingFor('generate');
        return this.streamOnRoute(binding, snapshot, route, request, queue);
      }),
    );
  }

  private async streamOnRoute(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
    request: GenerateStreamRequest,
    queue: ChunkQueue<string>,
  ): Promise<void> {
    assertStreamLive(request.signal);
    if (route.kind !== 'provider') {
      queue.push(
        await this.generateOnRoute(
          binding,
          snapshot,
          route,
          request.prompt,
          request.systemPrompt,
          undefined,
          cacheWhileLive(request),
        ),
      );
      return;
    }
    const key = this.streamCacheKey(binding, snapshot, route, request);
    const hit =
      key === undefined
        ? null
        : await this.operationCacheGet(key, this.modelOf(binding, route), 'generate');
    if (hit !== null) {
      queue.push(hit);
      return;
    }
    const opening = await this.runTransient('generate', route, () =>
      this.openFirstChunk(binding, snapshot, route, request),
    );
    await this.relayStream(opening, key, request, queue);
  }

  private streamCacheKey(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
    request: GenerateStreamRequest,
  ): string | undefined {
    if (this.operationCache === undefined) return undefined;
    return this.generateCacheKey(
      binding,
      snapshot,
      route,
      request.prompt,
      request.systemPrompt,
      undefined,
    );
  }

  private async openFirstChunk(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
    request: GenerateStreamRequest,
  ): Promise<StreamOpening> {
    const backend = await this.backendFor(binding, snapshot, route);
    if (backend.generateStream === undefined) {
      const whole = await backend.generate(
        request.prompt,
        request.systemPrompt,
        undefined,
        cacheWhileLive(request),
      );
      return { whole };
    }
    const stream = backend.generateStream(request.prompt, request.systemPrompt, request.signal);
    const rest = stream[Symbol.asyncIterator]();
    const first = await rest.next();
    if (first.done) throw new GenerationStreamInterruptedError(STREAM_EMPTY_CODE);
    return { first: first.value, rest };
  }

  private async relayStream(
    opening: StreamOpening,
    key: string | undefined,
    request: GenerateStreamRequest,
    queue: ChunkQueue<string>,
  ): Promise<void> {
    const head = 'whole' in opening ? opening.whole : opening.first;
    queue.push(head);
    try {
      const full = 'whole' in opening ? head : await this.relayRest(head, opening.rest, queue);
      assertStreamLive(request.signal);
      if (key !== undefined && request.shouldCache(full)) {
        await this.options.operationCache?.set(key, full);
      }
    } catch (error) {
      if ('rest' in opening) await opening.rest.return?.().catch(() => undefined);
      throw new GenerationStreamInterruptedError(
        TenantPolicyBoundInference.streamFailureCode(error),
      );
    }
  }

  private async relayRest(
    head: string,
    rest: AsyncIterator<string>,
    queue: ChunkQueue<string>,
  ): Promise<string> {
    let full = head;
    for (let next = await rest.next(); !next.done; next = await rest.next()) {
      queue.push(next.value);
      full += next.value;
    }
    return full;
  }

  private static streamFailureCode(error: unknown): string {
    if (
      error instanceof ProviderRouteError ||
      error instanceof GenerationStreamInterruptedError ||
      error instanceof ChunkQueueError
    ) {
      return error.code;
    }
    return STREAM_FAILED_CODE;
  }

  private async critiqueUnderPolicy(
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    return this.withFallback(this.routeChainFor('critique'), (route) =>
      this.admitted('critique', route, async () => {
        const { binding, snapshot } = await this.bindingFor('critique');
        return this.critiqueOnRoute(binding, snapshot, route, prompt, systemPrompt, shouldCache);
      }),
    );
  }

  private async critiqueOnRoute(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
    prompt: string,
    systemPrompt?: string,
    shouldCache?: (output: string) => boolean,
  ): Promise<string> {
    const cache = this.operationCache;
    const critiqueOnce = () =>
      this.runTransient('critique', route, async () =>
        (await this.backendFor(binding, snapshot, route)).critique(
          prompt,
          systemPrompt,
          shouldCache,
        ),
      );
    if (!cache) return critiqueOnce();
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
      route,
    );
    const hit = await this.operationCacheGet(key, this.modelOf(binding, route), 'generate');
    if (hit !== null) return hit;
    const output = await critiqueOnce();
    if ((shouldCache ?? (() => true))(output)) await this.options.operationCache?.set(key, output);
    return output;
  }

  private async judgeUnderPolicy(
    prompt: string,
    tool: ToolSpec,
    systemPrompt?: string,
  ): Promise<unknown> {
    return this.withFallback(this.routeChainFor('judge'), (route) =>
      this.admitted('judge', route, async () => {
        const { binding, snapshot } = await this.bindingFor('judge');
        return this.runTransient('judge', route, async () => {
          const structured = this.options.backendForVerifiedBinding
            ? (await this.backendFor(binding, snapshot, route)).generateStructured
            : this.options.structured;
          if (!structured) {
            throw this.refuse(
              snapshot,
              new TenantPolicyBoundInferenceError('active_policy_snapshot_refresh_failed'),
            );
          }
          return structured(prompt, tool, systemPrompt);
        });
      }),
    );
  }

  private async withFallback<T>(
    chain: readonly InferenceRoute[],
    attempt: (route: InferenceRoute) => Promise<T>,
  ): Promise<T> {
    const unanswered: InferenceOutageRecord[] = [];
    let index = 0;
    for (;;) {
      const route = chain[index] ?? ACI_ROUTE;
      const next = chain[index + 1];
      const tracked = inferenceOutageScope.attempt(() => attempt(route));
      try {
        const result = await tracked.result;
        inferenceOutageScope.discard(unanswered);
        return result;
      } catch (error) {
        if (
          next === undefined ||
          !(error instanceof ProviderRouteError && error.fallbackEligible)
        ) {
          throw error;
        }
        unanswered.push(...tracked.made());
        this.noteFallback(route, next);
        index += 1;
      }
    }
  }

  private noteFallback(from: InferenceRoute, to: InferenceRoute): void {
    this.logFallback(from, to);
    if (inferenceOutageScope.firstFallbackInMessage()) this.options.routeResolver?.noteFallback();
  }

  private logFallback(from: InferenceRoute, to: InferenceRoute): void {
    this.options.logger?.warn('inference_route_fallback', {
      ...(from.kind === 'provider' ? { purpose: from.purpose } : {}),
      model: this.catalogLabel(to),
    });
  }

  private catalogLabel(route: InferenceRoute): string {
    return route.kind === 'provider' ? route.model : 'aci';
  }

  private runTransient<T>(
    role: InferenceModelRole,
    route: InferenceRoute,
    operation: () => Promise<T>,
    statusesOverride?: ReadonlySet<number>,
  ): Promise<T> {
    return this.transientRetry.run(
      operation,
      this.retryWindows(role),
      this.backoffTimer(role, route),
      statusesOverride ??
        (route.kind === 'provider'
          ? PROVIDER_ROUTE_POLICY[route.provider].transientStatuses
          : undefined),
    );
  }

  private routeFor(role: InferenceModelRole): InferenceRoute {
    return this.routeChainFor(role)[0] ?? ACI_ROUTE;
  }

  private routeChainFor(role: InferenceModelRole): readonly InferenceRoute[] {
    return (
      this.options.routeResolver?.routeChain(
        role,
        inferencePurposeScope.current(),
        this.tenantId,
      ) ?? [ACI_ROUTE]
    );
  }

  private modelOf(binding: VerifiedActivePolicyRoleBindingV1, route: InferenceRoute): string {
    return route.kind === 'provider' ? route.model : binding.modelId;
  }

  private retryWindows(role: InferenceModelRole): TransientRetryWindows {
    return transientRetryWindows(role, this.options.latencyProfile ?? 'batch');
  }

  private backoffTimer(role: InferenceModelRole, route: InferenceRoute): BackoffObserver {
    return (backoff) => this.timed('retry_backoff', role, backoff, route);
  }

  private timed<T>(
    phase: InferenceCallPhase,
    role: InferenceModelRole,
    step: () => Promise<T>,
    route: InferenceRoute = this.routeFor(role),
  ): Promise<T> {
    const timer = this.options.timer;
    return timer ? timer(phase, this.callLabel(role, route), step) : step();
  }

  // An unconfigured role has no model id to report; its refusal is the binding's to raise, not the label's.
  private callLabel(role: InferenceModelRole, route: InferenceRoute): InferenceCallLabel {
    const label = { role, operation: INFERENCE_OPERATION_BY_ROLE[role] };
    if (route.kind === 'provider') return { model: route.model, ...label };
    if (role === 'embed' && !this.isLegacyEmbeddingSpace()) {
      return { model: OPENAI_EMBED_MODEL, ...label };
    }
    try {
      return { model: inferenceModel(role), ...label };
    } catch {
      return label;
    }
  }

  async authorize(role: InferenceModelRole): Promise<void> {
    await this.bindingFor(role);
  }

  private async backendFor(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    route: InferenceRoute,
  ): Promise<TenantPolicyOperationBackend> {
    return this.options.backendForVerifiedBinding
      ? this.options.backendForVerifiedBinding(binding, snapshot, route)
      : this.backend;
  }

  private cacheKey(
    binding: VerifiedActivePolicyRoleBindingV1,
    snapshot: VerifiedActivePolicySnapshotV1,
    operation: string,
    input: string,
    route: InferenceRoute,
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
      ...this.routeNamespace(route),
    });
    return llmCacheKey(this.modelOf(binding, route), namespace, input);
  }

  // A route that is not the policy's own adds its identity, so an entry never crosses routes.
  private routeNamespace(route: InferenceRoute): Record<string, unknown> {
    if (route.kind !== 'provider') return {};
    const prefix = inferencePurposeScope.current()?.cachedSystemPrefix;
    return {
      route: PROVIDER_ROUTE_POLICY[route.provider].cacheRouteLabel,
      routeModel: route.model,
      purpose: route.purpose,
      effort: route.effort,
      arm: route.arm,
      prefixDigest: prefix?.digest ?? null,
    };
  }

  private operationCacheGet(
    key: string,
    model: string,
    operation: InferenceOperation,
  ): Promise<string | null> {
    return this.replayFrom(this.operationCache, key, model, operation);
  }

  private async replayFrom(
    cache: LlmOperationCache | undefined,
    key: string,
    model: string,
    operation: InferenceOperation,
  ): Promise<string | null> {
    const hit = await cache?.get<string>(key);
    if (hit === null || hit === undefined) return null;
    this.recordReplay(model, operation);
    return hit;
  }

  private async replayVectorFrom(
    cache: LlmOperationCache | undefined,
    key: string,
    model: string,
    accept: (hit: readonly number[]) => boolean = () => true,
  ): Promise<number[] | null> {
    const hit = await cache?.getVector(key);
    if (hit === null || hit === undefined || !accept(hit)) return null;
    this.recordReplay(model, 'embed');
    return hit;
  }

  private recordReplay(model: string, operation: InferenceOperation): void {
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
  }

  private get operationCache(): LlmOperationCache | undefined {
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
    return this.timed('bind', role, () => this.bindUnderPolicy(role));
  }

  private async bindUnderPolicy(role: InferenceModelRole): Promise<{
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
    const verifiedInFull = await this.ensureFresh(role, snapshot, freshness, epoch);
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
    role: InferenceModelRole,
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
      const sample = await this.readTrustedTime(role, freshness, context, timeoutMs);
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

  // A settled read abandons its still-queued attestation turns, so an evicted read leaves none behind.
  private async readTrustedTime(
    role: InferenceModelRole,
    freshness: TenantPolicyFreshnessPort,
    context: TrustedTimeReadContext,
    timeoutMs: number,
  ): Promise<TrustedTimeSample> {
    const abandonRead = new AbortController();
    try {
      return await this.readWithRetry(
        (attemptSignal) =>
          attestationTurnScope.run(
            { priority: true, abandonRead: abandonRead.signal, abandonAttempt: attemptSignal },
            () => this.timed('trusted_time', role, () => freshness.trustedTime.read(context)),
          ),
        timeoutMs,
        (error) => this.isRefreshTimeout(error),
      );
    } finally {
      abandonRead.abort();
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
    read: (attemptSignal: AbortSignal) => Promise<T>,
    timeoutMs: number,
    retryable: (error: unknown) => boolean,
  ): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      const attemptAbort = new AbortController();
      try {
        return await this.withTimeout(read(attemptAbort.signal), timeoutMs, () =>
          attemptAbort.abort(),
        );
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

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    onTimeout?: () => void,
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timer = setTimeout(() => {
            onTimeout?.();
            reject(new Error(REFRESH_TIMEOUT_CODE));
          }, timeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
