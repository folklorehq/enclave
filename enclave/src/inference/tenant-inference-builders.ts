import type { Cache } from '@folklore/core';
import type { InferenceUsageSink } from '@folklore/inference';
import { CachedInference } from './CachedInference.js';
import { inferenceModel, phalaInference } from './phala.js';
import {
  TenantPolicyBoundInference,
  type TenantPolicyFreshnessPort,
  type TenantPolicyRuntimeEvidencePort,
  type TenantPolicySnapshotProvider,
  type TenantPolicyVerifiedBindingBackendFactory,
  type TenantPolicyVerifiedBindingForwarder,
} from './TenantPolicyBoundInference.js';
import { UnboundPoolInference } from './UnboundPoolInference.js';

export interface PoolPolicyPorts {
  freshnessFor(orgId: string): TenantPolicyFreshnessPort | undefined;
  runtimeEvidenceFor(orgId: string): TenantPolicyRuntimeEvidencePort | undefined;
  bindingForwarderFor(orgId: string): TenantPolicyVerifiedBindingForwarder | undefined;
  backendFor(orgId: string): TenantPolicyVerifiedBindingBackendFactory | undefined;
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
}

/** Each port reads its dependency when asked; poolPolicyBoundInference asks once, at construction. */
export function poolPolicyPortsFrom(deps: ActivePolicyPortDeps): PoolPolicyPorts {
  return {
    freshnessFor: (orgId) => deps.activePolicyFreshnessFor?.(orgId),
    runtimeEvidenceFor: (orgId) => deps.activePolicyRuntimeEvidenceFor?.(orgId),
    bindingForwarderFor: (orgId) => deps.activePolicyBindingForwarderFor?.(orgId),
    backendFor: (orgId) => deps.activePolicyBackendFor?.(orgId),
  };
}

/** The one construction of a pool tenant's inference: every policy guard required, no live fallback. */
export function poolPolicyBoundInference(input: {
  readonly orgId: string;
  readonly snapshot: TenantPolicySnapshotProvider;
  readonly policy: PoolPolicyPorts;
  readonly operationCache: Cache;
  readonly usageSink?: InferenceUsageSink;
}): TenantPolicyBoundInference {
  const { orgId, policy } = input;
  return new TenantPolicyBoundInference(orgId, input.snapshot, new UnboundPoolInference(), {
    freshnessProvider: () => policy.freshnessFor(orgId),
    requireFreshness: true,
    runtimeEvidence: policy.runtimeEvidenceFor(orgId),
    requireRuntimeEvidence: true,
    verifiedBindingForwarder: policy.bindingForwarderFor(orgId),
    requireBindingForwarding: true,
    backendForVerifiedBinding: policy.backendFor(orgId),
    operationCache: input.operationCache,
    ...(input.usageSink ? { usageSink: input.usageSink } : {}),
  });
}

/** A dedicated tenant's inference: the configured global backend behind its sealed cache. */
export function dedicatedCachedInference(
  cache: Cache,
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
