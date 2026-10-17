import { inferenceTrustPolicyV2Schema } from '@folklore/contracts';
import type { InferenceBackend, VerifiedActivePolicyRoleBindingV1 } from '@folklore/inference';
import type {
  TenantPolicyFreshnessPort,
  TenantPolicyOperationBackend,
  TenantPolicyVerifiedBindingBackendFactory,
} from './TenantPolicyBoundInference.js';
import { OperationAuthority } from './OperationAuthority.js';
import { createPublicAciOperationBackend } from './PublicAciOperationBackend.js';
import { createPinnedInferenceTransport } from '../egress/inference.js';
import { assertPublicInferenceEmbeddingDimension } from './phala.js';
import {
  publicAciOperationLimits,
  type InferenceLatencyProfile,
} from './public-aci-operation-limits.js';

export interface PublicAciRuntimeBackendFactoryOptions {
  readonly providerPolicy: unknown;
  readonly tenantId: string;
  readonly freshness: TenantPolicyFreshnessPort;
  readonly bootEpoch: string;
  readonly apiKey?: string;
  readonly latencyProfile?: InferenceLatencyProfile;
  readonly fetchFactory?: (policy: {
    origin: string;
    route: string;
    tlsSpkiSha256: readonly string[];
  }) => { fetch: typeof fetch; close: () => Promise<void> };
  readonly backendFactory?: typeof createPublicAciOperationBackend;
}

export function createPublicAciRuntimeBackendFactory(
  options: PublicAciRuntimeBackendFactoryOptions,
): TenantPolicyVerifiedBindingBackendFactory {
  const policy = inferenceTrustPolicyV2Schema.parse(options.providerPolicy);
  if (policy.version !== 2 || policy.evidence.profile !== 'dstack-tdx-public-v1')
    throw new Error('public_aci_provider_policy_mismatch');
  const makeBackend = options.backendFactory ?? createPublicAciOperationBackend;
  const makeTransport =
    options.fetchFactory ??
    ((p) =>
      createPinnedInferenceTransport({
        ...p,
        route: policy.route,
        tlsSpkiSha256: [...p.tlsSpkiSha256],
      }));
  const authority = new OperationAuthority({
    tenantId: options.tenantId,
    freshness: options.freshness,
    bootEpoch: options.bootEpoch,
    latencyProfile: options.latencyProfile,
    providerPolicyGeneration: policy.generation,
  });
  return async (binding, snapshot): Promise<TenantPolicyOperationBackend> => {
    const admission = await authority.admit(binding, snapshot, {
      afterRoleCheck: assertPublicInferenceEmbeddingDimension,
    });
    const { role, trustedTimeContext, trustedTime, remainingBudget } = admission;
    const limits = publicAciOperationLimits(binding.role, options.latencyProfile ?? 'batch');
    const transport = makeTransport({
      origin: policy.origin,
      route: policy.route,
      tlsSpkiSha256: snapshot.policy.channel.tlsSpkiSha256,
    });
    let backend: InferenceBackend;
    try {
      backend = makeBackend({
        providerPolicy: policy,
        snapshot,
        binding,
        trustedTime,
        trustedTimeContext,
        keysetHighWater: admission.authority,
        fetchImpl: (input, init) => {
          const deadlineSignal = AbortSignal.timeout(remainingBudget());
          const signal = init?.signal
            ? AbortSignal.any([init.signal, deadlineSignal])
            : deadlineSignal;
          return transport.fetch(input, { ...init, signal });
        },
        apiKey: options.apiKey,
        requestTimeoutMs: limits.requestTimeoutMs,
      });
    } catch (error) {
      await transport.close();
      throw error;
    }
    let consumed = false;
    const invoke = async <T>(
      operationRole: VerifiedActivePolicyRoleBindingV1['role'],
      fn: () => Promise<T>,
    ): Promise<T> => {
      if (consumed) throw new Error('public_aci_operation_consumed');
      consumed = true;
      try {
        if (binding.role !== operationRole) throw new Error('public_aci_operation_role_mismatch');
        await trustedTime.read(trustedTimeContext);
        remainingBudget();
        const result = await fn();
        remainingBudget();
        return result;
      } finally {
        await Promise.all([backend.close(), transport.close()]);
      }
    };
    const generationOptions = (
      systemPrompt?: string,
      temperature = role.capabilities.temperature,
    ) => {
      const maxTokens = role.capabilities.maxOutputTokens;
      if (
        maxTokens === null ||
        !Number.isSafeInteger(maxTokens) ||
        maxTokens <= 0 ||
        !Number.isFinite(temperature) ||
        temperature !== role.capabilities.temperature
      ) {
        throw new Error('public_aci_generation_capability_mismatch');
      }
      return {
        model: binding.modelId,
        modelRevision: binding.modelRevision,
        modelRole: binding.role,
        systemPrompt,
        temperature,
        maxTokens,
      };
    };
    return {
      embed: (text) =>
        invoke('embed', async () => {
          const dimension = role.capabilities.embeddingDimension;
          if (dimension === null || !Number.isSafeInteger(dimension) || dimension <= 0)
            throw new Error('public_aci_embedding_capability_mismatch');
          const vector = await backend.embed(text, {
            model: binding.modelId,
            modelRevision: binding.modelRevision,
            modelRole: 'embed',
          });
          if (vector.length !== dimension || vector.some((value) => !Number.isFinite(value)))
            throw new Error('public_aci_embedding_dimension_mismatch');
          return vector;
        }),
      generate: (prompt, systemPrompt, temperature) =>
        invoke('generate', () =>
          backend.generate(prompt, generationOptions(systemPrompt, temperature)),
        ),
      critique: (prompt, systemPrompt) =>
        invoke('critique', () => backend.generate(prompt, generationOptions(systemPrompt))),
      generateStructured: (prompt, tool, systemPrompt) =>
        invoke('judge', () => {
          if (!role.capabilities.structuredOutput || backend.generateStructured === undefined)
            throw new Error('public_aci_structured_output_forbidden');
          return backend.generateStructured(prompt, { ...generationOptions(systemPrompt), tool });
        }),
    };
  };
}
