import type { InferenceModelRole, InferenceTimer, InferenceUsageSink } from '@folklore/inference';
import { CachedInference } from './CachedInference.js';
import { inferenceModel, phalaInference } from './phala.js';
import {
  TenantPolicyBoundInference,
  type TenantPolicyFreshnessPort,
  type TenantPolicyRuntimeEvidencePort,
  type TenantPolicySnapshotProvider,
  type TenantPolicyVerifiedBindingBackendFactory,
  type TenantPolicyVerifiedBindingForwarder,
  type UpstreamCallGate,
} from './TenantPolicyBoundInference.js';
import { UnboundPoolInference } from './UnboundPoolInference.js';
import type { EmbeddingProvider } from './openai/OpenAIEmbedRouteComposition.js';
import type { InferenceRoute, InferenceRouteResolver } from './routing/InferenceRouteResolver.js';
import { logger } from '../logger.js';
import type { LlmOperationCache } from './vector-cache.js';
import type { InferenceLatencyProfile } from './public-aci-operation-limits.js';

export interface PoolPolicyPorts {
  freshnessFor(orgId: string): TenantPolicyFreshnessPort | undefined;
  runtimeEvidenceFor(orgId: string): TenantPolicyRuntimeEvidencePort | undefined;
  bindingForwarderFor(orgId: string): TenantPolicyVerifiedBindingForwarder | undefined;
  backendFor(orgId: string): TenantPolicyVerifiedBindingBackendFactory | undefined;
  readonly routeResolver?: InferenceRouteResolver;
  readonly embeddingProvider?: EmbeddingProvider;
}

export interface ActivePolicyPortDeps {
  readonly activePolicyFreshnessFor?: (orgId: string) => TenantPolicyFreshnessPort | undefined;
  readonly activePolicyRuntimeEvidenceFor?: (
    orgId: string,
  ) => TenantPolicyRuntimeEvidencePort | undefined;
  readonly activePolicyBindingForwarderFor?: (
    orgId: string,
  ) => TenantPolicyVerifiedBindingForwarder | undefined;
  readonly activePolicyBackendFor?: (
    orgId: string,
  ) => TenantPolicyVerifiedBindingBackendFactory | undefined;
  readonly claudeRoutes?: InferenceRouteResolver;
  readonly embeddingProvider?: EmbeddingProvider;
}

/** Each port reads its dependency when asked; poolPolicyBoundInference asks once, at construction. */
export function poolPolicyPortsFrom(deps: ActivePolicyPortDeps): PoolPolicyPorts {
  return {
    freshnessFor: (orgId) => deps.activePolicyFreshnessFor?.(orgId),
    runtimeEvidenceFor: (orgId) => deps.activePolicyRuntimeEvidenceFor?.(orgId),
    bindingForwarderFor: (orgId) => deps.activePolicyBindingForwarderFor?.(orgId),
    backendFor: (orgId) => deps.activePolicyBackendFor?.(orgId),
    ...(deps.claudeRoutes === undefined ? {} : { routeResolver: deps.claudeRoutes }),
    ...(deps.embeddingProvider === undefined ? {} : { embeddingProvider: deps.embeddingProvider }),
  };
}

/** The one construction of a pool tenant's inference: every policy guard required, no live fallback. */
export function poolPolicyBoundInference(input: {
  readonly orgId: string;
  readonly snapshot: TenantPolicySnapshotProvider;
  readonly policy: PoolPolicyPorts;
  readonly operationCache: LlmOperationCache;
  readonly usageSink?: InferenceUsageSink;
  readonly timer?: InferenceTimer;
  readonly latencyProfile?: InferenceLatencyProfile;
  readonly upstreamGate?: UpstreamCallGate;
}): TenantPolicyBoundInference {
  const { orgId, policy } = input;
  return new TenantPolicyBoundInference(orgId, input.snapshot, new UnboundPoolInference(), {
    logger,
    freshnessProvider: () => policy.freshnessFor(orgId),
    requireFreshness: true,
    runtimeEvidence: policy.runtimeEvidenceFor(orgId),
    requireRuntimeEvidence: true,
    verifiedBindingForwarder: policy.bindingForwarderFor(orgId),
    requireBindingForwarding: true,
    backendForVerifiedBinding: policy.backendFor(orgId),
    operationCache: input.operationCache,
    ...(policy.embeddingProvider === undefined
      ? {}
      : { embeddingProvider: policy.embeddingProvider }),
    ...(input.usageSink ? { usageSink: input.usageSink } : {}),
    ...(input.timer ? { timer: input.timer } : {}),
    ...(input.latencyProfile ? { latencyProfile: input.latencyProfile } : {}),
    ...(input.upstreamGate ? { upstreamGate: input.upstreamGate } : {}),
    ...(policy.routeResolver === undefined
      ? {}
      : {
          routeResolver: policy.routeResolver,
          upstreamKeyFor: (role: InferenceModelRole) =>
            policy.routeResolver?.upstreamKeyFor(role, orgId),
          upstreamKeyForRoute: (route: InferenceRoute) =>
            policy.routeResolver?.upstreamKeyOfRoute(route),
        }),
  });
}

/** A dedicated tenant's inference: the configured global backend behind its sealed cache. */
export function dedicatedCachedInference(
  cache: LlmOperationCache,
  promptVersion: string,
  usageSink?: InferenceUsageSink,
): CachedInference {
  return new CachedInference(
    phalaInference,
    cache,
    {
      embedModel: inferenceModel('embed'),
      generateModel: inferenceModel('generate'),
      critiqueModel: inferenceModel('critique'),
      promptVersion,
    },
    usageSink,
  );
}
