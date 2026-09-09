import { inferenceTrustPolicyV2Schema } from '@folklore/contracts';
import type {
  AciTrustContext,
  InferenceBackend,
  TrustedTimeAuthorityPort,
  TrustedTimeReadContext,
  TrustedTimeSample,
  VerifiedActivePolicyRoleBindingV1,
  VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import {
  assertVerifiedActivePolicyRoleBindingV1,
  assertVerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import type {
  TenantPolicyFreshnessPort,
  TenantPolicyOperationBackend,
  TenantPolicyVerifiedBindingBackendFactory,
} from './TenantPolicyBoundInference.js';
import { PublicAciPinnedKeysetAuthority } from './PublicAciPinnedKeysetAuthority.js';
import { createPublicAciOperationBackend } from './PublicAciOperationBackend.js';
import { createPinnedInferenceTransport } from '../egress/inference.js';

// Leave ten seconds of headroom below the NSM checkpoint maximum age.
const PUBLIC_ACI_OPERATION_BUDGET_MS = 50_000;

export interface PublicAciRuntimeBackendFactoryOptions {
  readonly providerPolicy: unknown;
  readonly tenantId: string;
  readonly freshness: TenantPolicyFreshnessPort;
  readonly bootEpoch: string;
  readonly apiKey?: string;
  readonly fetchFactory?: (policy: {
    origin: string;
    route: string;
    tlsSpkiSha256: readonly string[];
  }) => { fetch: typeof fetch; close: () => Promise<void> };
  readonly backendFactory?: typeof createPublicAciOperationBackend;
}

function exactRole(
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
) {
  const role = snapshot.policy.roles[binding.role];
  if (
    snapshot.tenantId !== binding.orgId ||
    binding.orgId !== snapshot.orgId ||
    binding.deploymentId !== snapshot.deploymentId ||
    snapshot.roleBindingFor(binding.role) !== binding ||
    role.model !== binding.modelId ||
    role.modelRevision !== binding.modelRevision
  )
    throw new Error('public_aci_role_binding_mismatch');
  return role;
}

function millisecondsTrustedTime(
  source: TrustedTimeAuthorityPort,
  context: AciTrustContext,
  role: { establishedAt: number; expiresAt: number },
  snapshot: VerifiedActivePolicySnapshotV1,
): TrustedTimeAuthorityPort {
  return {
    read: async (requested: TrustedTimeReadContext = {}): Promise<TrustedTimeSample> => {
      const sample = await source.read({
        orgId: context.orgId,
        deploymentId: context.deploymentId,
      });
      const ms = sample.trustedNow;
      if (
        !Number.isSafeInteger(ms) ||
        ms <= 0 ||
        sample.orgId !== context.orgId ||
        sample.deploymentId !== context.deploymentId ||
        sample.bootEpoch !== context.bootEpoch ||
        sample.checkpointDigest !== context.checkpointDigest ||
        ms < role.establishedAt ||
        ms >= role.expiresAt ||
        ms >= snapshot.policy.lifetime.snapshotExpiresAt ||
        (requested.orgId !== undefined && requested.orgId !== sample.orgId) ||
        (requested.deploymentId !== undefined && requested.deploymentId !== sample.deploymentId) ||
        (requested.bootEpoch !== undefined && requested.bootEpoch !== sample.bootEpoch) ||
        (requested.checkpointDigest !== undefined &&
          requested.checkpointDigest !== sample.checkpointDigest)
      )
        throw new Error('public_aci_operation_time_invalid');
      return { ...sample, trustedNow: Math.floor(ms / 1000) };
    },
  };
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
  return async (binding, snapshot): Promise<TenantPolicyOperationBackend> => {
    assertVerifiedActivePolicySnapshotV1(snapshot);
    assertVerifiedActivePolicyRoleBindingV1(binding);
    if (
      snapshot.orgId !== options.tenantId ||
      snapshot.tenantId !== options.tenantId ||
      binding.orgId !== options.tenantId
    )
      throw new Error('public_aci_tenant_mismatch');
    const role = exactRole(binding, snapshot);
    const startedAt = performance.now();
    const remainingBudget = () => {
      const remaining = Math.floor(
        PUBLIC_ACI_OPERATION_BUDGET_MS - (performance.now() - startedAt),
      );
      if (remaining <= 0) throw new Error('public_aci_operation_deadline');
      return remaining;
    };
    const sample = await options.freshness.trustedTime.read({
      orgId: snapshot.orgId,
      deploymentId: snapshot.deploymentId,
    });
    if (
      sample.orgId !== snapshot.orgId ||
      sample.deploymentId !== snapshot.deploymentId ||
      sample.bootEpoch !== options.bootEpoch
    )
      throw new Error('public_aci_trusted_time_context_mismatch');
    const expectedContext = options.freshness.expectedContext();
    const trustedTimeContext: AciTrustContext = {
      orgId: sample.orgId,
      deploymentId: sample.deploymentId,
      bootEpoch: sample.bootEpoch,
      checkpointDigest: sample.checkpointDigest,
    };
    const authority = new PublicAciPinnedKeysetAuthority({
      snapshot,
      expectedContext,
      durable: options.freshness.highWater,
      trustedTimeContext,
    });
    remainingBudget();
    const transport = makeTransport({
      origin: policy.origin,
      route: policy.route,
      tlsSpkiSha256: snapshot.policy.channel.tlsSpkiSha256,
    });
    const trustedTime = millisecondsTrustedTime(
      options.freshness.trustedTime,
      trustedTimeContext,
      role,
      snapshot,
    );
    let backend: InferenceBackend;
    try {
      backend = makeBackend({
        providerPolicy: policy,
        snapshot,
        binding,
        trustedTime,
        trustedTimeContext,
        keysetHighWater: authority,
        fetchImpl: (input, init) => {
          const deadlineSignal = AbortSignal.timeout(remainingBudget());
          const signal = init?.signal
            ? AbortSignal.any([init.signal, deadlineSignal])
            : deadlineSignal;
          return transport.fetch(input, { ...init, signal });
        },
        apiKey: options.apiKey,
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
