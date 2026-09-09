import { inferenceTrustPolicyV2Schema } from '@folklore/contracts';
import {
  OpenAICompatBackend,
  PublicAciReportVerifier,
  PublicAciResponseVerifier,
  PublicAciSessionVerifier,
  assertVerifiedActivePolicyRoleBindingV1,
  assertVerifiedActivePolicySnapshotV1,
  type AciKeysetHighWaterAuthorityPort,
  type AciTrustContext,
  type InferenceBackend,
  type TrustedTimeAuthorityPort,
  type VerifiedActivePolicyRoleBindingV1,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import { recordTokenUsage } from './TokenUsageScope.js';

import { createPublicDstackQuoteVerifier } from '../attestation/PublicDstackQuoteComposition.js';

const PUBLIC_ACI_REQUEST_TIMEOUT_MS = 40_000;

export interface PublicAciOperationBackendOptions {
  readonly providerPolicy: unknown;
  readonly snapshot: VerifiedActivePolicySnapshotV1;
  readonly binding: VerifiedActivePolicyRoleBindingV1;
  readonly trustedTime: TrustedTimeAuthorityPort;
  readonly trustedTimeContext: AciTrustContext;
  readonly keysetHighWater: AciKeysetHighWaterAuthorityPort;
  readonly fetchImpl: typeof fetch;
  readonly apiKey?: string;
}

/** One backend per already-authorized tenant operation. No process-global request state. */
export function createPublicAciOperationBackend(
  options: PublicAciOperationBackendOptions,
): InferenceBackend {
  assertVerifiedActivePolicySnapshotV1(options.snapshot);
  assertVerifiedActivePolicyRoleBindingV1(options.binding);
  const policy = inferenceTrustPolicyV2Schema.parse(options.providerPolicy);
  const { snapshot, binding } = options;
  const role = snapshot.policy.roles[binding.role];
  const selected = policy.roleModels[binding.role];
  const endpoint = binding.role === 'embed' ? '/v1/embeddings' : '/v1/chat/completions';
  if (
    policy.evidence.profile !== 'dstack-tdx-public-v1' ||
    policy.route !== '/v1' ||
    snapshot.roleBindingFor(binding.role) !== binding ||
    binding.orgId !== snapshot.orgId ||
    binding.deploymentId !== snapshot.deploymentId ||
    policy.generation !== snapshot.policyGeneration ||
    selected.model !== binding.modelId ||
    selected.revision !== binding.modelRevision ||
    role.model !== binding.modelId ||
    role.modelRevision !== binding.modelRevision ||
    policy.origin !== snapshot.policy.route.origin ||
    (snapshot.policy.route.path !== policy.route && snapshot.policy.route.path !== endpoint) ||
    snapshot.policy.route.method !== 'POST' ||
    snapshot.policy.route.redirectOrigins.length !== 0 ||
    options.trustedTimeContext.orgId !== snapshot.orgId ||
    options.trustedTimeContext.deploymentId !== snapshot.deploymentId
  ) {
    throw new Error('public_aci_tenant_policy_mismatch');
  }
  const context = Object.freeze({ ...options.trustedTimeContext });
  const readOperationTime = async (): Promise<number> => {
    const time = await options.trustedTime.read(context);
    const nowMs = time.trustedNow * 1_000;
    if (
      time.orgId !== context.orgId ||
      time.deploymentId !== context.deploymentId ||
      time.bootEpoch !== context.bootEpoch ||
      time.checkpointDigest !== context.checkpointDigest ||
      !Number.isSafeInteger(time.trustedNow) ||
      time.trustedNow <= 0 ||
      !Number.isSafeInteger(nowMs) ||
      nowMs < role.establishedAt ||
      nowMs >= role.expiresAt ||
      nowMs >= snapshot.policy.lifetime.snapshotExpiresAt
    )
      throw new Error('public_aci_operation_time_invalid');
    return time.trustedNow;
  };
  const transport: typeof fetch = async (input, init) => {
    const supplied =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(supplied);
    if (url.origin !== policy.origin) throw new Error('public_aci_origin_mismatch');
    const headers = new Headers(init?.headers);
    if (options.apiKey !== undefined) headers.set('authorization', `Bearer ${options.apiKey}`);
    return options.fetchImpl(input, { ...init, headers, redirect: 'error' });
  };
  const report = new PublicAciReportVerifier({
    baseUrl: `${policy.origin}${policy.route}`,
    policy,
    activationGeneration: snapshot.activationGeneration,
    fetchImpl: transport,
    trustedTimeAuthority: options.trustedTime,
    trustedTimeContext: context,
    keysetHighWaterAuthority: options.keysetHighWater,
    publicQuoteVerifier: createPublicDstackQuoteVerifier(),
  });
  const sessions = new PublicAciSessionVerifier(transport);
  const response = new PublicAciResponseVerifier({
    reportVerifier: report,
    policy,
    fetchImpl: transport,
    verifySession: async ({ receipt, keyset, evidence }) => {
      if (
        evidence.model !== binding.modelId ||
        evidence.modelRevision !== binding.modelRevision ||
        (evidence.modelRole ?? 'generate') !== binding.role ||
        keyset.workloadKeysetDigest !== `sha256:${snapshot.durableCheckpoint.keysetDigest}`
      )
        throw new Error('public_aci_operation_binding_mismatch');
      const trustedNow = await readOperationTime();
      if (
        receipt.served_at > trustedNow + policy.clockSkewSeconds ||
        trustedNow - receipt.served_at > policy.maxSessionLifetimeSeconds ||
        trustedNow >= keyset.notAfter
      )
        throw new Error('public_aci_response_time_invalid');
      const result = await sessions.verify({
        receipt,
        keyset,
        trustedNow,
        policy: {
          origin: policy.origin,
          workloadKeysetDigest: keyset.workloadKeysetDigest,
          model: binding.modelId,
          channelKeyDigest: role.channelKeyDigest,
          maxSessionLifetimeSeconds: policy.maxSessionLifetimeSeconds,
          requiredSessionClaims: [
            ...new Set([...policy.requiredSessionClaims, ...role.requiredSessionClaims]),
          ],
          permittedClaimSources: policy.permittedClaimSources.filter((source) =>
            role.permittedClaimSources.includes(source),
          ),
        },
      });
      if (result.sessionId !== role.sessionId) throw new Error('public_aci_role_session_mismatch');
      return result;
    },
  });
  return new OpenAICompatBackend({
    baseUrl: `${policy.origin}${policy.route}`,
    apiKey: options.apiKey,
    embedModel: policy.roleModels.embed.model,
    embedModelRevision: policy.roleModels.embed.revision,
    generateModel: selected.model,
    generateModelRevision: selected.revision,
    modelAllowlist: [binding.modelId],
    publicAciRequired: true,
    timeoutMs: PUBLIC_ACI_REQUEST_TIMEOUT_MS,
    usageSink: recordTokenUsage,
    responseVerifier: {
      ensureAttested: async (request) => {
        if (
          request === undefined ||
          request.model !== binding.modelId ||
          request.endpoint !== endpoint ||
          request.modelRevision !== binding.modelRevision ||
          (request.modelRole ?? 'generate') !== binding.role
        )
          throw new Error('public_aci_operation_binding_mismatch');
        await readOperationTime();
        await response.ensureAttested(request);
      },
      verifyReceipt: (id, evidence) => response.verifyReceipt(id, evidence),
    },
    fetchImpl: transport,
  });
}
