import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { KMSClient } from '@aws-sdk/client-kms';
import { SQSClient } from '@aws-sdk/client-sqs';
import { SSMClient, PutParameterCommand, GetParameterCommand } from '@aws-sdk/client-ssm';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { awsClientTransport } from './aws/aws-transport.js';
import { TenantContextFactory } from './tenant/TenantContextFactory.js';
import { TenantRegistry } from './tenant/tenant-registry.js';
import {
  resolveBootAssignments,
  parseAssignmentManifestWire,
} from './tenant/tenant-assignments.js';
import { TenantAssignmentApplier } from './tenant/TenantAssignmentApplier.js';
import { TenantRequestQuiescer } from './tenant/TenantRequestQuiescer.js';
import { TenantRequestQuiescenceMonitor } from './tenant/TenantRequestQuiescenceMonitor.js';
import { TenantMessageRouter } from './tenant/tenant-message-router.js';
import { HttpCanaryAuthorizationConsumer } from './ingest/HttpCanaryAuthorizationConsumer.js';
import { QueueSetDrainer } from './tenant/QueueSetDrainer.js';
import { saveAllTenantIndices } from './tenant/index-persistence.js';
import { createTenantResolver } from './tenant/tenant-resolver.js';
import { BoxServer } from './http/BoxServer.js';
import { SynthesisConsumer } from './workers/SynthesisConsumer.js';
import { fetchLinkPreview } from './preview/preview-client.js';
import { HaltGate, poolHaltKey, tenantHaltKey } from './control/HaltGate.js';
import { ActivityMonitor } from './control/ActivityMonitor.js';
import { EnclaveFactRetriever } from './retrieval/EnclaveFactRetriever.js';
import { EnclaveFactAnswerer } from './workers/EnclaveFactAnswerer.js';
import { EnclaveWikiContentDecryptor } from './wiki/EnclaveWikiContentDecryptor.js';
import { EnclaveWikiEditSealer } from './wiki/EnclaveWikiEditSealer.js';
import { EnclaveWikiPublicationSealer } from './wiki/EnclaveWikiPublicationSealer.js';
import {
  EnclaveWikiCommentSealer,
  EnclaveWikiFeedbackSealer,
  EnclaveWikiSnapshotSealer,
} from './wiki/content-sealers.js';
import {
  assertInferenceConfigured,
  assertInferenceAttestationEcho,
  configureInferenceAttestation,
  configureLocalInferencePolicy,
  inferenceModel,
  phalaInference,
  setInferenceTelemetry,
  setInferenceTrustPolicy,
  setVerifiedInferenceReceiptSink,
} from './inference/phala.js';
import { currentInferenceReceiptContext } from './inference/inference-receipt-context.js';
import {
  ANSWER_CACHE_VERSION,
  CachedInference,
  type InferenceModel,
} from './inference/CachedInference.js';
import { S3LlmCache } from './inference/S3LlmCache.js';
import { installGlobalEgressDispatcher } from './egress/proxy.js';
import {
  createContainer,
  createRuntimeDatabaseConnection,
  createRuntimeDatabaseReadiness,
  type ApiContainer,
  type CreateContainerOptions,
  type RetrieverDeps,
} from '@folklore/api';
import { NoopTelemetryClient } from '@folklore/telemetry';
import { RedisCache } from '@folklore/cache';
import { logger } from './logger.js';
import {
  BufferedOpsTelemetryClient,
  inferenceReceiptProofPayload,
  RedisOpsEventChannel,
  type InferenceReceiptProof,
  type PoolTenantUsage,
} from '@folklore/control-plane';
import {
  assignmentAckPayload,
  assignmentAckSchema,
  assignmentStorageProofPayload,
  poolAssignmentAckKey,
  poolAssignmentGenerationFloorKey,
  poolAssignmentsKey,
  type CanaryAuthorizationOutcomeProof,
  type NormalizedAssignmentManifestV1,
} from '@folklore/contracts';
import type { RuntimeDatabaseConfig } from '@folklore/contracts/enclave-attestation';
import { sha256Hex } from '@folklore/utils';
import {
  createRuntimeAttestationComposition,
  enableRuntimeAttestation,
  initializeRuntimeAttestationForBoot,
  startRuntimeAttestation,
} from './attestation/runtime-attestation-composition.js';
import type { VerifiedBootManifest } from './attestation/BootManifestVerifier.js';
import {
  VerifiedBootPolicyStateLoader,
  buildVerifiedBootGenerationContext,
} from './attestation/VerifiedBootPolicyStateLoader.js';
import {
  BootStateActivePolicyReferenceVerifier,
  createEnclaveActivePolicyKeyVerifier,
} from './inference/BootStateActivePolicyReferenceVerifier.js';
import {
  DurableGenerationHighWaterClient,
  type DurableGenerationHighWaterTransport,
  type DurableGenerationHighWaterVerifierPort,
} from './inference/DurableGenerationHighWaterClient.js';
import { DurableGenerationHighWaterClientAdapter } from './inference/DurableGenerationHighWaterClientAdapter.js';
import {
  ActivePolicyCarrierVerifier,
  VerifiedActivePolicySnapshotVerifier,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import { createOAuthRuntime, createPinnedControlPlaneFetch } from './pull/oauth-composition.js';
import { evictMintedTokensForOrg, resetMintedTokenCache } from './pull/pull-runner.js';
import { GitHubCodebaseConnectionResolver } from './codebase/GitHubCodebaseConnectionResolver.js';
import { CodebaseSelectionStore } from './codebase/CodebaseSelectionStore.js';
import { EnclaveCodebaseSettingsAdapter } from './codebase/EnclaveCodebaseSettingsAdapter.js';
import type { EnclaveOAuthIngress } from './pull/EnclaveOAuthIngress.js';
import type { JiraWebhookLifecycleService } from './pull/JiraWebhookLifecycleService.js';
import type { JiraWebhookAuthenticator } from './ingest/JiraWebhookAuthenticator.js';
import type { WebhookLifecycleDelivery } from '@folklore/contracts/enclave';
import { BootManifestSecretLoader } from './attestation/BootManifestSecretLoader.js';
import {
  AwsBootManifestSecretsManager,
  AwsBootManifestSsmParameters,
} from './attestation/boot-manifest-secret-clients.js';
import { getAttestationDoc } from './sealing/nsm.js';
import { decryptRecipientCiphertextWithKeyId } from './sealing/seal.js';
import { deriveIngestKeypair } from './sealing/keygen.js';
import { devMasterKeySealers } from './sealing/dev-master-key-sealers.js';
import {
  KmsRecipientDecryptor,
  RuntimeDatabaseCredentialConsumer,
  SsmRuntimeDatabaseParameters,
  type RuntimeDatabaseConnection,
} from './runtime-database/RuntimeDatabaseCredentialConsumer.js';
import { RuntimeDatabaseLease } from './runtime-database/RuntimeDatabaseLease.js';
import { PoolRuntimeAttestationService } from './attestation/pool/PoolRuntimeAttestationService.js';
import { RuntimeAttestationServer } from './attestation/RuntimeAttestationServer.js';
import { NodeRuntimeAttestationListener } from './attestation/NodeRuntimeAttestationListener.js';
import { DEFAULT_ENCLAVE_ATTESTATION_PORT } from './attestation/runtime-attestation-composition.js';
import { StorageCanaryProof } from './tenant/StorageCanaryProof.js';
import {
  assignmentManifestPublicKeyForVerifiedBoot,
  verifyAssignmentManifestWire,
  type VerifiedAssignmentManifest,
} from './tenant/VerifiedAssignmentManifest.js';
import {
  DEVELOPMENT_ENCLAVE_OUTPUT_KEY,
  Ed25519EnclaveOutputAuthenticator,
} from '@folklore/crypto';

// route external egress through the parent CONNECT proxy — before any client is
// built, so undici SDKs pick up the dispatcher (loopback bypasses it, keeping AWS/inference).
installGlobalEgressDispatcher();

const REGION = process.env['AWS_REGION']!;
const SEALED_BLOB_BUCKET = process.env['SEALED_BLOB_BUCKET'] ?? '';
const PROCESSED_OUTPUTS_BUCKET = process.env['PROCESSED_OUTPUTS_BUCKET'] ?? '';
const PROCESSED_QUEUE_URL = process.env['PROCESSED_QUEUE_URL'] ?? '';
const RAW_PAYLOADS_BUCKET = process.env['RAW_PAYLOADS_BUCKET'] ?? '';
const SYNTHESIS_REQUEST_QUEUE_URL = process.env['SYNTHESIS_REQUEST_QUEUE_URL'] ?? '';
const TEE_API_KEY_SSM_PATH = process.env['TEE_API_KEY_SSM_PATH'] ?? '';
// pull transports run in-enclave. The control plane only ever hands back
// ciphertext (source OAuth tokens ECIES-encrypted to this enclave's public key);
// this shared deployment secret (the same one `apps/agent` uses to check in) is
// what authenticates the enclave's fetch of those encrypted connections.
const CONTROL_PLANE_URL = process.env['CONTROL_PLANE_URL'] ?? '';
const DEPLOYMENT_ID = process.env['DEPLOYMENT_ID'] ?? '';
const OUTPUT_DEPLOYMENT_ID =
  DEPLOYMENT_ID || (process.env['NODE_ENV'] === 'development' ? 'development' : '');
const AGENT_TOKEN_SSM_PATH = process.env['AGENT_TOKEN_SSM_PATH'] ?? '';
const OAUTH_PROVIDER_CONFIG_JSON = process.env['OAUTH_PROVIDER_CONFIG_JSON'] ?? '';
// Break-glass halt flag lives in the shared Redis, reached over the in-enclave
// vsock proxy. Required — the enclave refuses to boot without it (see below).
const REDIS_URL = process.env['REDIS_URL'] ?? '';

// After 15 consecutive empty long-polls (~5 min) across ALL assigned queues the enclave signals idle.
const IDLE_POLL_THRESHOLD = 15;
// How long after a member's last authenticated request the host still counts as in use — reading a
// wiki produces no queue traffic, so without this a reader between page loads looks like a quiet host.
const ACTIVITY_QUIET_WINDOW_MS = 60 * 60 * 1000;

// Dev-only forcePathStyle: localstack doesn't parse bare `*.localhost` virtual-host buckets, so
// the S3 client must address path-style against it. Production (unset) keeps virtual-host, unchanged.
const s3 = new S3Client({
  region: REGION,
  ...awsClientTransport(),
  forcePathStyle: process.env['ENCLAVE_S3_FORCE_PATH_STYLE'] === 'true',
});
const sqs = new SQSClient({ region: REGION, ...awsClientTransport() });
const ssm = new SSMClient({ region: REGION, ...awsClientTransport() });
const kms = new KMSClient({ region: REGION, ...awsClientTransport() });
const secretsManager = new SecretsManagerClient({ region: REGION, ...awsClientTransport() });

async function loadInferenceKey(): Promise<void> {
  if (!TEE_API_KEY_SSM_PATH || process.env['TEE_API_KEY']) return;
  try {
    const resp = await ssm.send(
      new GetParameterCommand({ Name: TEE_API_KEY_SSM_PATH, WithDecryption: true }),
    );
    if (resp.Parameter?.Value) process.env['TEE_API_KEY'] = resp.Parameter.Value;
  } catch (err) {
    logger.error('failed to load inference key from SSM', { err });
  }
}

async function loadAgentToken(): Promise<void> {
  if (!AGENT_TOKEN_SSM_PATH || process.env['AGENT_TOKEN']) return;
  try {
    const resp = await ssm.send(
      new GetParameterCommand({ Name: AGENT_TOKEN_SSM_PATH, WithDecryption: true }),
    );
    if (resp.Parameter?.Value) process.env['AGENT_TOKEN'] = resp.Parameter.Value;
  } catch (err) {
    logger.error('failed to load agent token from SSM', { err });
  }
}

// A shared pool (POOL_ID set) learns its assigned tenants from the content-free manifest on the
// check-in channel (§4.3); a dedicated box (default tier §6.1) is env-configured. So POOL_ID + empty
// env is valid — it boots with zero tenants and the applier fills the registry from the manifest.
const POOL_ID = process.env['POOL_ID']?.trim() ?? '';

const ASSIGNMENT_MANIFEST_PUBLIC_KEY = process.env['ASSIGNMENT_MANIFEST_PUBLIC_KEY'] ?? '';

// Stage 2 (design §5): each assigned tenant gets its own single-CMK context, keyed in the registry
// by tenantId so no keyed op can reach another tenant's material. The applier is the one path that
// builds/tears down contexts — used for the boot set here and for live (re)assignment below (§4.3).
const bootAssignments = resolveBootAssignments(process.env);
// Pool-scoped idle (§5): the wake Lambda tracks the pool, so a shared host reports idle under the
// pool path; a dedicated box keeps its per-tenant path so N=1 behavior is unchanged.
const idleSsmPath = POOL_ID
  ? `/folklore/pool/${POOL_ID}/idle`
  : `/folklore/${bootAssignments[0]!.tenantId}/idle`;

// Dev-only: localstack KMS can't do the Nitro Recipient decrypt, so ENCLAVE_DEV_KMS_STUB swaps in
// AES-GCM seal/unseal with DATA_KEK. devMasterKeySealers fails closed outside development/test.
const devKmsStub = process.env['ENCLAVE_DEV_KMS_STUB'] === 'true';

// Set once the boot manifest is verified, which happens after this factory is constructed but
// before anything seals a mnemonic — hence the accessor rather than a value (audit F2). Held here
// rather than read back off runtimeAttestation because enable/start null that handle on failure,
// and a later first boot must not read a discarded manifest as an absent one.
let verifiedBootManifest: VerifiedBootManifest | undefined;

const tenantFactory = new TenantContextFactory({
  s3,
  region: REGION,
  sealedBlobBucket: SEALED_BLOB_BUCKET,
  processedOutputsBucket: PROCESSED_OUTPUTS_BUCKET,
  signedRecoveryPubkey: () => (POOL_ID ? undefined : verifiedBootManifest?.recoveryPubkey),
  signedStorageKeyArn: () => (POOL_ID ? undefined : verifiedBootManifest?.storageKeyArn),
  ...(devKmsStub
    ? devMasterKeySealers(process.env['NODE_ENV'] ?? '', process.env['DATA_KEK'])
    : {}),
});
const registry = new TenantRegistry();
const tenantRequests = new TenantRequestQuiescer();
// Late-bound: the synthesis consumer and the answer-inference cache are composed further down, but
// the applier must be able to evict a torn-down tenant's resident theme index + LLM-cache RAM front
// the moment it drops it (§2.2 pt 5) - zeroize() only wipes the TenantContext's OWN handles, not a
// separately-held S3LlmCache/EnclaveCrypto reference this map captured earlier.
let synthesisConsumer: SynthesisConsumer | undefined;
let apiContainer: ApiContainer | undefined;
const drainerRef: { current?: QueueSetDrainer } = {};
let verifiedPoolManifest: VerifiedAssignmentManifest | undefined;
const runtimeDatabaseLease = new RuntimeDatabaseLease<ApiContainer, RuntimeDatabaseConnection>({
  requestRestart: (exitCode) => process.exit(exitCode),
});
let activateRuntimeDatabase: ((config: RuntimeDatabaseConfig) => Promise<void>) | undefined;
let runtimeDatabaseActivation: Promise<void> | undefined;
let evictAnswerInference: ((tenantId: string) => Promise<void>) | undefined;
const assignmentApplier = new TenantAssignmentApplier(
  registry,
  (identity) => tenantFactory.build(identity),
  logger,
  async (tenantId) => {
    const requestDrain = tenantRequests.fence(tenantId);
    const teardown = [
      drainerRef.current?.evictTenant(tenantId),
      synthesisConsumer?.evictTenant(tenantId),
      evictAnswerInference?.(tenantId),
      apiContainer?.evictCollabTenant(tenantId),
    ].filter((result): result is Promise<void> => result !== undefined);
    try {
      const results = await Promise.allSettled([requestDrain, ...teardown]);
      if (results.some((result) => result.status === 'rejected')) {
        throw new Error('tenant_subsystem_teardown_failed');
      }
    } finally {
      evictMintedTokensForOrg(tenantId);
    }
  },
  undefined,
  DEPLOYMENT_ID,
  (tenantId) => {
    drainerRef.current?.finishTenantEviction(tenantId);
    synthesisConsumer?.finishTenantEviction(tenantId);
    tenantRequests.activate(tenantId);
  },
  async (tenantId) => {
    const requestDrain = tenantRequests.fence(tenantId);
    try {
      const results = await Promise.allSettled(
        [
          requestDrain,
          drainerRef.current?.evictTenant(tenantId),
          synthesisConsumer?.evictTenant(tenantId),
          evictAnswerInference?.(tenantId),
          apiContainer?.evictCollabTenant(tenantId),
        ].filter((result): result is Promise<void> => result !== undefined),
      );
      if (results.some((result) => result.status === 'rejected')) {
        throw new Error('tenant_generation_quiesce_failed');
      }
    } finally {
      evictMintedTokensForOrg(tenantId);
    }
  },
  (tenantId) => {
    drainerRef.current?.finishTenantEviction(tenantId);
    synthesisConsumer?.finishTenantEviction(tenantId);
    tenantRequests.activate(tenantId);
  },
  (tenantId, phase) => {
    logger.fatal('tenant_quiescence_failed', { tenant_id: tenantId, phase });
    process.exit(1);
  },
);
// Plan Task 2: the verified active-policy snapshot provider is the only boot-to-gateway policy
// authority. It stays undefined until a boot manifest carries a signed active-policy carrier,
// and any invocation fails closed while the durable high-water transport is unavailable.
let verifiedActivePolicySnapshotProvider:
  | (() => Promise<VerifiedActivePolicySnapshotV1>)
  | undefined;
// PR5 non-activation: the evidence recorder factory stays unavailable until H4. No evidence
// session is injected and no explicit enablement is passed, so this composition root never
// exposes the evidence recorder, and enclave/src/index.ts must not call the factory while the
// evidence seam is dormant.
let runtimeAttestation =
  createRuntimeAttestationComposition({
    env: process.env,
    secretLoader: new BootManifestSecretLoader(
      new AwsBootManifestSecretsManager(secretsManager),
      new AwsBootManifestSsmParameters(ssm),
      {
        recipientDecryptor: {
          decryptForRecipient: async ({ ciphertext, keyId, encryptionContext }) =>
            (await decryptRecipientCiphertextWithKeyId(ciphertext, keyId, encryptionContext))
              .plaintext,
        },
      },
    ),
    nsm: { attest: getAttestationDoc },
    s3,
    isTenantAssigned: () => registry.size > 0,
    isTenantApiReady: () => apiContainer !== undefined,
    getIngestPublicKey: () => {
      const context = registry.all()[0];
      return context ? deriveIngestKeypair(context.masterKey).publicKeyRaw : Uint8Array.from([]);
    },
    getRuntimeDatabaseReceipt: () => runtimeDatabaseLease.receipt(),
    logger: logger.child({ component: 'attestation' }),
  }) ?? null;
runtimeAttestation = await initializeRuntimeAttestationForBoot(
  runtimeAttestation,
  async (prepared) => {
    verifiedBootManifest = prepared?.verifiedManifest();
    const bootManifest = verifiedBootManifest;
    const activePolicyCarrier = bootManifest?.activePolicyCarrier;
    if (bootManifest && activePolicyCarrier) {
      // Plan Task 2: production policy verification is built only from the verified boot policy
      // state loader, the shared carrier verifier adapter, and the durable high-water adapter.
      // No policy object, reference URL, receipt metadata, environment variable, or assignment
      // metadata is accepted as policy authority. The provider is dormant until the gated
      // gateway composition invokes it; the high-water transport is unavailable, so any
      // invocation fails closed rather than authorizing with an unverified floor.
      const sharedCarrierVerifier = new ActivePolicyCarrierVerifier(
        createEnclaveActivePolicyKeyVerifier(),
      );
      const referenceVerifier = new BootStateActivePolicyReferenceVerifier(sharedCarrierVerifier);
      const loader = new VerifiedBootPolicyStateLoader({
        verifiedManifest: bootManifest,
        carrierVerifier: referenceVerifier,
      });
      const highWaterAdapter = new DurableGenerationHighWaterClientAdapter(
        new DurableGenerationHighWaterClient(
          unavailableHighWaterTransport(),
          unavailableHighWaterVerifier(),
        ),
      );
      const snapshotVerifier = new VerifiedActivePolicySnapshotVerifier({
        carrierVerifier: referenceVerifier,
        highWater: highWaterAdapter,
      });
      verifiedActivePolicySnapshotProvider = async () => {
        const bootState = await loader.loadVerifiedBootPolicyState();
        return snapshotVerifier.verify({
          bootState,
          expectedContext: buildVerifiedBootGenerationContext(bootManifest, activePolicyCarrier),
        });
      };
    }
    const signedPolicy = verifiedBootManifest?.inferenceAttestation;
    const trustPolicy = verifiedBootManifest?.inferenceTrustPolicy;
    if (process.env['NODE_ENV'] === 'production' && !signedPolicy && !trustPolicy) {
      throw new Error('signed_inference_trust_policy_unavailable');
    }
    if (trustPolicy) setInferenceTrustPolicy(trustPolicy);
    if (signedPolicy) configureInferenceAttestation(signedPolicy);
    else if (!trustPolicy) configureLocalInferencePolicy();
    if (process.env['NODE_ENV'] === 'production' && POOL_ID) {
      assignmentManifestPublicKeyForVerifiedBoot(
        verifiedBootManifest,
        ASSIGNMENT_MANIFEST_PUBLIC_KEY,
      );
    }
    await assignmentApplier.apply(bootAssignments);
  },
  logger.child({ component: 'attestation' }),
);
const poolRuntimeAttestation = POOL_ID
  ? new PoolRuntimeAttestationService(
      () => ({
        poolDeploymentId: DEPLOYMENT_ID,
        assignmentGeneration: verifiedPoolManifest?.generation ?? 0,
        assignmentDigest: verifiedPoolManifest?.digest ?? '',
        assignmentManifestVerified: verifiedPoolManifest !== undefined,
        tenantAssigned: registry.size > 0,
        tenantApiReady: apiContainer !== undefined,
        runtimeDatabase: runtimeDatabaseLease.receipt(),
      }),
      { attest: getAttestationDoc },
    )
  : undefined;
const poolRuntimeAttestationListener = poolRuntimeAttestation
  ? new NodeRuntimeAttestationListener(
      Number(process.env['ENCLAVE_ATTESTATION_PORT'] ?? '') || DEFAULT_ENCLAVE_ATTESTATION_PORT,
    )
  : undefined;
const poolRuntimeAttestationServer = poolRuntimeAttestation
  ? new RuntimeAttestationServer({ collect: (nonce) => poolRuntimeAttestation.collect(nonce) })
  : undefined;
console.log('tenant contexts assigned', { count: registry.size });

await loadInferenceKey();
setInferenceTrustPolicy(verifiedBootManifest?.inferenceTrustPolicy);
assertInferenceConfigured();
await loadAgentToken();

const outputAuthenticator = createEnclaveOutputAuthenticator();

function outputAssignmentGeneration(): number {
  const generation = POOL_ID
    ? assignmentApplier.generation()
    : (verifiedBootManifest?.configurationGeneration ?? 0);
  if (!Number.isSafeInteger(generation) || generation < 1) {
    if (process.env['NODE_ENV'] === 'development') return 1;
    throw new Error('enclave_output_identity_unavailable');
  }
  return generation;
}

// Per-request keyring selection from the verified JWT orgId (design §4.2): every read/synthesis
// path resolves its TenantContext through this one choke point, which fails closed (403) on an
// orgId not in the assigned set BEFORE any keyring is reachable. No single boot-time "box context".
const resolveTenant = createTenantResolver(registry);

let oauthIngress: EnclaveOAuthIngress | undefined;
let refreshOAuthCredential:
  | ((
      input: import('@folklore/contracts/enclave').OAuthRefreshCommand,
    ) => Promise<import('@folklore/contracts/enclave').OAuthRefreshMetadataUpdate>)
  | undefined;
let mintGitHubInstallationToken:
  | ((input: { installationId: string }) => Promise<{ accessToken: string; expiresAt: string }>)
  | undefined;
let jiraWebhookLifecycle: JiraWebhookLifecycleService | undefined;
let jiraWebhookAuthenticator: JiraWebhookAuthenticator | undefined;
let recordJiraWebhookDelivery:
  | ((input: WebhookLifecycleDelivery) => Promise<'updated' | 'stale' | 'invalid_submission'>)
  | undefined;
if (OAUTH_PROVIDER_CONFIG_JSON) {
  throw new Error('oauth_ingress_disabled_untrusted_boot_manifest');
}
const verifiedManifest = runtimeAttestation?.verifiedManifest();
const controlPlaneIdentity = verifiedManifest?.controlPlaneIdentity;
const controlPlaneFetch = controlPlaneIdentity
  ? createPinnedControlPlaneFetch(globalThis.fetch, controlPlaneIdentity)
  : undefined;
const enabledOAuthProviders =
  verifiedManifest?.oauthProviders.filter((provider) => provider.enabled) ?? [];
const jiraOAuthProvider = enabledOAuthProviders.find((provider) => provider.kind === 'jira');
if (process.env['OAUTH_INGRESS_REQUIRED'] === 'true' && enabledOAuthProviders.length === 0) {
  throw new Error('oauth_ingress_manifest_providers_unavailable');
}
if (enabledOAuthProviders.length > 0) {
  const identity = controlPlaneIdentity;
  if (!verifiedManifest || !identity) throw new Error('oauth_control_plane_identity_unavailable');
  const secretReferences = new Map(
    verifiedManifest.secretReferences.map((reference) => [reference.id, reference]),
  );
  for (const provider of enabledOAuthProviders) {
    const reference = secretReferences.get(provider.secretReferenceId);
    if (!reference || reference.store !== 'secrets-manager') {
      throw new Error('oauth_provider_secret_reference_invalid');
    }
  }
  const runtime = createOAuthRuntime({
    controlPlaneUrl: identity.origin,
    controlPlaneIdentity: identity,
    deploymentId: verifiedManifest.deploymentId,
    agentToken: () => process.env['AGENT_TOKEN'] ?? '',
    authorizationToken: process.env['AGENT_TOKEN'] ?? '',
    providerConfigs: enabledOAuthProviders.map((provider) => ({
      ...provider,
      allowedHosts: [...provider.allowedHosts],
    })),
    jiraWebhookMode: jiraOAuthProvider?.jiraWebhookMode ?? 'off',
    jiraWebhookPilotOrgIds: jiraOAuthProvider?.jiraWebhookPilotOrgIds,
    jiraWebhookClaimPolicy: jiraOAuthProvider?.jiraWebhookClaimPolicy,
    resolveTenant,
    getSecretValue: async ({ secretId }) => {
      const reference = secretReferences.get(secretId);
      if (!reference || reference.store !== 'secrets-manager') {
        throw new Error('oauth_provider_secret_reference_invalid');
      }
      const response = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: reference.arn, VersionId: reference.versionId }),
      );
      if (
        response.ARN !== reference.arn ||
        response.VersionId !== reference.versionId ||
        !response.SecretBinary
      ) {
        throw new Error('oauth_provider_secret_version_mismatch');
      }
      return typeof response.SecretBinary === 'string'
        ? Buffer.from(response.SecretBinary, 'base64')
        : Buffer.from(response.SecretBinary);
    },
    kmsKeyId: verifiedManifest.kmsKeyArn,
    s3,
  });
  oauthIngress = runtime.ingress;
  refreshOAuthCredential = runtime.refreshOAuthCredential;
  mintGitHubInstallationToken = runtime.mintGitHubInstallationToken;
  jiraWebhookLifecycle = runtime.jiraWebhookLifecycle;
  jiraWebhookAuthenticator = runtime.jiraWebhookAuthenticator;
  recordJiraWebhookDelivery = runtime.recordJiraWebhookDelivery;
}

const boxServer = new BoxServer(undefined, {
  httpPort: Number(process.env['ENCLAVE_HTTP_PORT'] ?? '') || undefined,
  ...(oauthIngress ? { oauthIngress: oauthIngress.fetch } : {}),
});

// the break-glass halt and billing suspension gate every dequeue. Without a
// halt gate the loop would drain/decrypt fail-open, so refuse to boot rather than run ungated.
if (!DEPLOYMENT_ID || !REDIS_URL) {
  throw new Error(
    'refusing to start: halt gate unavailable (DEPLOYMENT_ID and REDIS_URL required)',
  );
}
const haltCache = new RedisCache(REDIS_URL);
const storageCanaryProof = new StorageCanaryProof({
  async put(bucket, key, body) {
    await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body }));
  },
  async get(bucket, key) {
    const response = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    if (!response.Body) throw new Error('storage_canary_read_failed');
    return Buffer.from(await response.Body.transformToByteArray());
  },
});
// Pool-wide emergency halt (unchanged single-tenant semantics); per-tenant gates are built on demand
// (§6.3) since the assigned set changes live, so halting tenant A never stops tenant B's queue.
const poolHalt = new HaltGate(
  haltCache,
  DEPLOYMENT_ID,
  logger,
  POOL_ID ? [poolHaltKey(POOL_ID)] : [],
);
const evictTenantSubsystems = async (tenantId: string): Promise<void> => {
  const results = await Promise.allSettled(
    [
      drainerRef.current?.evictTenant(tenantId),
      synthesisConsumer?.evictTenant(tenantId),
      evictAnswerInference?.(tenantId),
      apiContainer?.evictCollabTenant(tenantId),
    ].filter((result): result is Promise<void> => result !== undefined),
  );
  if (results.some((result) => result.status === 'rejected')) {
    throw new Error('tenant_subsystem_quiescence_failed');
  }
};
const tenantRequestQuiescence = new TenantRequestQuiescenceMonitor({
  cache: haltCache,
  quiescer: tenantRequests,
  tenantIds: () => registry.all().map((context) => context.tenantId),
  logger,
  onFence: evictTenantSubsystems,
  onActivate: (tenantId) => {
    drainerRef.current?.finishTenantEviction(tenantId);
    synthesisConsumer?.finishTenantEviction(tenantId);
  },
});
const beginTenantRequest = async (tenantId: string) => {
  const halted = await new HaltGate(haltCache, DEPLOYMENT_ID, logger, [
    tenantHaltKey(tenantId),
    ...(POOL_ID ? [poolHaltKey(POOL_ID)] : []),
  ]).isHalted();
  if (halted) return undefined;
  return tenantRequests.begin(tenantId);
};

// §4.3: the agent publishes this pool's content-free manifest to Redis on check-in; the enclave
// re-reads it and rebuilds the registry (add/remove tenants, §2.2 pt 5). Idempotent, so a periodic
// re-read reconverges to the latest assignment. Dedicated boxes have no POOL_ID and no manifest.
async function refreshAssignments(): Promise<void> {
  if (!POOL_ID) return;
  try {
    const manifest = await haltCache.get(poolAssignmentsKey(POOL_ID));
    if (!manifest) return;
    let parsed: NormalizedAssignmentManifestV1;
    try {
      parsed = parseAssignmentManifestWire(manifest, POOL_ID, assignmentApplier.generation());
    } catch (err) {
      if (!(err instanceof Error) || err.message !== 'assignment_manifest_stale') throw err;
      const replay = parseAssignmentManifestWire(
        manifest,
        POOL_ID,
        assignmentApplier.generation() - 1,
      );
      if (replay.poolId !== POOL_ID || !assignmentApplier.matchesCurrentManifest(replay)) throw err;
      parsed = replay;
    }
    const floor = await haltCache.get<unknown>(poolAssignmentGenerationFloorKey(POOL_ID));
    if (
      typeof floor !== 'number' ||
      !Number.isSafeInteger(floor) ||
      floor < 1 ||
      parsed.generation !== floor
    ) {
      throw new Error('assignment_manifest_generation_floor_mismatch');
    }
    const verified = verifyAssignmentManifestWire(
      parsed,
      assignmentManifestPublicKeyForVerifiedBoot(
        verifiedBootManifest,
        ASSIGNMENT_MANIFEST_PUBLIC_KEY,
      ),
    );
    assertInferenceAttestationEcho(verified.inferenceAttestation);
    if (process.env['NODE_ENV'] === 'production' && !verified.runtimeDatabase) {
      throw new Error('runtime_database_signed_config_unavailable');
    }
    if (process.env['NODE_ENV'] === 'production' && verified.runtimeDatabase) {
      const recovery = await runtimeDatabaseLease.reconcile(verified.runtimeDatabase);
      if (recovery === 'restart-requested') return;
      if (!runtimeDatabaseLease.api() && activateRuntimeDatabase) {
        await activateRuntimeDatabase(verified.runtimeDatabase);
      }
      apiContainer = runtimeDatabaseLease.api();
    }
    const result = assignmentApplier.matchesCurrentManifest(verified)
      ? { applied: true as const, generation: parsed.generation }
      : await assignmentApplier.applyManifest(verified);
    if (!result.applied) return;
    verifiedPoolManifest = verified;
    if (!runtimeAttestation && !poolRuntimeAttestation) {
      throw new Error('runtime_attestation_not_ready');
    }
    const successfulTenantIds: string[] = [];
    for (const context of [...registry.all()].sort((left, right) =>
      left.tenantId.localeCompare(right.tenantId),
    )) {
      successfulTenantIds.push(await storageCanaryProof.prove(context, parsed.generation));
    }
    const unsignedAcknowledgment = {
      poolId: parsed.poolId,
      generation: parsed.generation,
      digest: parsed.digest,
      assignmentWire: parsed.wire,
      ...(parsed.wire === 'SignedAssignmentManifestV3'
        ? { assignmentPayload: 'AssignmentManifestV3Payload' as const }
        : {}),
      floorGeneration: parsed.generation,
      floorDigest: parsed.digest,
      healthy: true,
      ingestPublicKeys: Object.fromEntries(
        registry
          .all()
          .map((context): readonly [string, string] => [
            context.tenantId,
            Buffer.from(deriveIngestKeypair(context.masterKey).publicKeyRaw).toString('hex'),
          ])
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)),
      ),
      storageProofVersion: 1 as const,
      storageProofTenantCount: successfulTenantIds.length,
      storageProofDigest: sha256Hex(
        assignmentStorageProofPayload(parsed.digest, successfulTenantIds),
      ),
    };
    const acknowledgmentPayload = Buffer.from(assignmentAckPayload(unsignedAcknowledgment), 'utf8');
    let signed: { publicKey: Uint8Array; signature: Uint8Array };
    try {
      if (POOL_ID) {
        if (!poolRuntimeAttestation) throw new Error('runtime_attestation_not_ready');
        signed = await poolRuntimeAttestation.signCurrent(acknowledgmentPayload);
      } else {
        if (!runtimeAttestation) throw new Error('runtime_attestation_not_ready');
        signed = runtimeAttestation.signAssignmentAck(acknowledgmentPayload);
      }
    } catch (error: unknown) {
      if (error instanceof Error && error.message === 'runtime_attestation_not_ready') {
        return;
      }
      throw error;
    }
    const acknowledgment = assignmentAckSchema.parse({
      ...unsignedAcknowledgment,
      signature: {
        publicKey: Buffer.from(signed.publicKey).toString('base64'),
        signature: Buffer.from(signed.signature).toString('base64'),
      },
    });
    await haltCache.set(poolAssignmentAckKey(POOL_ID), acknowledgment);
    logger.info('assignment manifest applied', unsignedAcknowledgment);
  } catch (err) {
    if (err instanceof Error && err.message === 'assignment_manifest_stale') return;
    // Log the error NAME only, never the raw error — a message could echo manifest field values.
    // A bad/foreign manifest leaves the current assignment set untouched — fail closed, don't tear
    // down live tenants on a parse slip.
    logger.error('assignment manifest refresh failed', {
      pool_id: POOL_ID,
      error: err instanceof Error ? err.name : 'unknown',
    });
  }
}

await refreshAssignments();
void tenantRequestQuiescence.runForever();
assertInferenceConfigured();
const ASSIGNMENT_REFRESH_INTERVAL_MS = 30_000;
// Bound how long shutdown waits for an in-flight synth to settle so a hung inference can't starve
// the fact-index save; on timeout we proceed WITHOUT freeing a still-pinned index (shred at exit).
const SHUTDOWN_QUIESCE_TIMEOUT_MS = 10_000;
const assignmentRefreshTimer = setInterval(
  () => void refreshAssignments(),
  ASSIGNMENT_REFRESH_INTERVAL_MS,
);

// the enclave has no PostHog egress, so ops telemetry (attestation failures, receipt
// verifications, model-gate rejections) is buffered onto the shared Redis list the box agent
// drains into its content-free check-in.
const opsEventChannel = new RedisOpsEventChannel(haltCache.redis, DEPLOYMENT_ID);
const opsTelemetry = new BufferedOpsTelemetryClient(opsEventChannel);
setInferenceTelemetry(opsTelemetry);
setVerifiedInferenceReceiptSink(async (sessionId) => {
  const context = currentInferenceReceiptContext();
  if (!context) return;
  const sessionPublicKey = poolRuntimeAttestation
    ? await poolRuntimeAttestation.currentSessionPublicKey()
    : runtimeAttestation?.sessionPublicKey();
  if (!sessionPublicKey) return;
  const unsigned = {
    name: 'inference.receipt_verified' as const,
    session_id: sessionId,
    canary_run_id: context.canary_run_id,
    request_id: context.request_id,
    deployment_id: DEPLOYMENT_ID,
    attestation_session_key_sha256: sha256Hex(Buffer.from(sessionPublicKey)),
  };
  const payload = Buffer.from(inferenceReceiptProofPayload(unsigned), 'utf8');
  const signed = poolRuntimeAttestation
    ? await poolRuntimeAttestation.signCurrent(payload)
    : runtimeAttestation?.signAssignmentAck(payload);
  if (!signed) return;
  const proof: InferenceReceiptProof = {
    ...unsigned,
    signature: Buffer.from(signed.signature).toString('base64'),
  };
  await opsEventChannel.push(proof);
});

const canaryProofSink = async (proof: CanaryAuthorizationOutcomeProof): Promise<void> => {
  await opsEventChannel.pushRequired({ name: 'canary.authorization_outcome_proof', ...proof });
};

// Queue emptiness alone does not mean nobody is here: members read and edit through the box API,
// and synthesis runs long after its message is gone. This is what the drain loop's idle check
// consults so a self-stop can't land on a live session.
const activityMonitor = new ActivityMonitor({ quietWindowMs: ACTIVITY_QUIET_WINDOW_MS });

async function resolveInteractiveCodebaseConnection(orgId: string) {
  if (!controlPlaneIdentity || !controlPlaneFetch || !mintGitHubInstallationToken) {
    throw new Error('codebase_selection_unavailable');
  }
  const tenant = resolveTenant(orgId);
  const scope = tenant.codebaseSelectionScope();
  const resolver = new GitHubCodebaseConnectionResolver({
    controlPlaneUrl: controlPlaneIdentity.origin,
    runtimeDeploymentId: DEPLOYMENT_ID,
    tenantDeploymentId: scope.deploymentId,
    agentToken: process.env['AGENT_TOKEN'] ?? '',
    orgId,
    crypto: tenant.crypto,
    fetchImpl: controlPlaneFetch,
    selectionStore: new CodebaseSelectionStore({
      s3,
      bucket: scope.bucket,
      crypto: scope.crypto,
    }),
  });
  const resolved = await resolver.resolveInteractive();
  if (resolved.outcome !== 'ready') throw new Error(resolved.reason);
  return { connection: resolved.connection, scope };
}

function createCodebaseSettingsPort() {
  if (!mintGitHubInstallationToken) throw new Error('codebase_selection_unavailable');
  return new EnclaveCodebaseSettingsAdapter({
    s3,
    resolveTenant,
    resolveConnection: resolveInteractiveCodebaseConnection,
    mintGitHubInstallationToken,
  });
}

// the box API is composed and served in-process. Every /api/* request
// reads decrypted content over the in-enclave Postgres proxy and never leaves.
try {
  // search is served by the in-enclave retriever — embed, ANN over the loaded
  // index, decrypt, and audience-gate, all in-process. The retriever resolves its tenant's
  // index + keyring per request from `params.orgId` (§4.2), so it serves every assigned
  // tenant from one instance without a union keyring.
  const buildRetriever = (retrieverDeps: RetrieverDeps) =>
    new EnclaveFactRetriever({
      ...retrieverDeps,
      resolveTenant,
      s3,
      processedBucket: PROCESSED_OUTPUTS_BUCKET,
      processedBucketFor: (orgId) => resolveTenant(orgId).processedOutputsBucket,
    });
  // Content-addressed, ESDK-sealed per-org LLM cache in front of phala (determinism #1):
  // a repeated question over an unchanged fact set replays without a fresh TEE call. Resolved PER
  // REQUEST from the answer's orgId (§4.2) — never a boot-time context — so the cache blob is sealed
  // and read under the requesting tenant's own key/orgId AAD and can't cross tenants. Memoized per
  // org (each entry uses only that tenant's crypto), mirroring the synthesis workers' cache. The
  // S3LlmCache reference is kept alongside the wrapper (not just the InferenceModel) so a tenant
  // eviction can close its RAM front and drop the entry's hold on that tenant's crypto - see
  // evictAnswerInference below.
  const answerInferenceByOrg = new Map<string, { inference: InferenceModel; cache: S3LlmCache }>();
  const answerInferenceFor = (orgId: string): InferenceModel => {
    let entry = answerInferenceByOrg.get(orgId);
    if (!entry) {
      const tenant = resolveTenant(orgId); // fail-closed (403) on an unassigned org before any keyring
      const cache = new S3LlmCache({
        s3,
        crypto: tenant.crypto,
        bucket: tenant.processedOutputsBucket || PROCESSED_OUTPUTS_BUCKET,
        orgId,
      });
      const inference = new CachedInference(phalaInference, cache, {
        embedModel: inferenceModel('embed'),
        generateModel: inferenceModel('generate'),
        critiqueModel: inferenceModel('critique'),
        promptVersion: ANSWER_CACHE_VERSION,
      });
      entry = { inference, cache };
      answerInferenceByOrg.set(orgId, entry);
    }
    return entry.inference;
  };
  // A removed tenant's crypto/decrypted-answer RAM cache must not outlive its assignment: zeroize()
  // only reaches the TenantContext's own handles, not this map's independently-held S3LlmCache.
  evictAnswerInference = async (tenantId) => {
    const entry = answerInferenceByOrg.get(tenantId);
    if (!entry) return;
    answerInferenceByOrg.delete(tenantId);
    await entry.cache.close();
  };
  const apiOptions: CreateContainerOptions = {
    // content-touching enclave opens no data-carrying egress — box-API telemetry inert by composition, not by omitting POSTHOG_API_KEY.
    telemetry: new NoopTelemetryClient(),
    controlPlaneJwks:
      controlPlaneIdentity && controlPlaneFetch
        ? { origin: controlPlaneIdentity.origin, fetch: controlPlaneFetch }
        : undefined,
    // The box API serves reads for every assigned tenant; the verified JWT orgId must be in the
    // assigned set (else 403) — this gate runs before any handler touches a keyring (§4.2 step 2).
    isAssignedOrg: (orgId: string) => registry.has(orgId),
    // The API reports activity only from behind its own auth gate: /api/* takes unauthenticated
    // traffic from anywhere, and a scanner hitting it must not be able to hold this host awake.
    onAuthenticatedRequest: () => activityMonitor.touch(),
    beginTenantRequest,
    codebaseSettings: createCodebaseSettingsPort(),
    retrieverFactory: buildRetriever,
    // grounded answers reuse the same per-request gated retrieval spine, then feed only
    // audience-visible decrypted bodies to the in-enclave TEE model — nothing leaves the enclave.
    // Both seams resolve per request from the answer's own orgId: the retriever and the sealed
    // generate cache above, so neither can bind to a boot-time tenant.
    answerServiceFactory: (retrieverDeps) =>
      new EnclaveFactAnswerer(
        buildRetriever(retrieverDeps),
        (orgId, prompt, systemPrompt, shouldCache) =>
          answerInferenceFor(orgId).generate(prompt, systemPrompt, undefined, shouldCache),
      ),
    // synthesized wiki text is ciphertext at rest; the read path decrypts audience-visible
    // blocks here, in-enclave, over the requesting tenant's sealed key (resolved from `ref.orgId`).
    wikiContentDecryptor: new EnclaveWikiContentDecryptor(resolveTenant),
    // mined draft→edit prose is sealed to the requesting tenant's key, in-enclave only.
    wikiEditSealer: new EnclaveWikiEditSealer(resolveTenant),
    wikiPublicationSealer: new EnclaveWikiPublicationSealer(resolveTenant),
    // live-collab Yjs snapshots, comments, and feedback corrections are sealed to the
    // requesting tenant's key, in-enclave only.
    wikiSnapshotSealer: new EnclaveWikiSnapshotSealer(resolveTenant),
    wikiCommentSealer: new EnclaveWikiCommentSealer(resolveTenant),
    wikiFeedbackSealer: new EnclaveWikiFeedbackSealer(resolveTenant),
  };
  const signedRuntimeDatabase: RuntimeDatabaseConfig | undefined =
    verifiedPoolManifest?.runtimeDatabase ?? verifiedManifest?.runtimeDatabase;
  if (process.env['NODE_ENV'] === 'production') {
    const activate = async (config: RuntimeDatabaseConfig): Promise<void> => {
      const recovery = await runtimeDatabaseLease.reconcile(config);
      if (recovery === 'restart-requested') return;
      if (runtimeDatabaseLease.api()) {
        apiContainer = runtimeDatabaseLease.api();
        return;
      }
      let candidate: ApiContainer | undefined;
      const consumed = await new RuntimeDatabaseCredentialConsumer({
        parameters: new SsmRuntimeDatabaseParameters(ssm),
        recipientDecryptor: new KmsRecipientDecryptor(kms, getAttestationDoc),
        createDatabase: createRuntimeDatabaseConnection,
        readiness: createRuntimeDatabaseReadiness(async (database) => {
          candidate = createContainer({ ...apiOptions, database });
          try {
            await candidate.start();
            const response = await candidate.app.request('/health');
            if (response.status === 200) return true;
          } catch {
            await candidate.close().catch(() => undefined);
            candidate = undefined;
            return false;
          }
          await candidate.close().catch(() => undefined);
          candidate = undefined;
          return false;
        }),
      }).consume(config, registry.all()[0]?.tenantId ?? config.envelope.poolDeploymentId);
      if (!candidate) {
        await consumed.database.close();
        throw new Error('runtime_database_api_unavailable');
      }
      runtimeDatabaseLease.activate(config, consumed.receipt, candidate, consumed.database);
      apiContainer = runtimeDatabaseLease.api();
      if (apiContainer && boxServer) {
        boxServer.attachApi(apiContainer.app.fetch, apiContainer.collabPort);
      }
    };
    activateRuntimeDatabase = (config) => {
      if (runtimeDatabaseActivation) return runtimeDatabaseActivation;
      const activation = activate(config);
      runtimeDatabaseActivation = activation;
      const clearActivation = (): void => {
        if (runtimeDatabaseActivation === activation) runtimeDatabaseActivation = undefined;
      };
      void activation.then(clearActivation, clearActivation);
      return activation;
    };
    if (!signedRuntimeDatabase) throw new Error('runtime_database_signed_config_unavailable');
    await activateRuntimeDatabase(signedRuntimeDatabase);
  } else {
    apiContainer = createContainer(apiOptions);
    await apiContainer.start();
  }
} catch (err) {
  // Degraded, not silent: the SPA still serves but /api/* returns 503 and /health reports
  // api:unavailable so the outage is observable, rather than a crash-looping boot.
  logger.error('BOX_API_DEGRADED', { err });
}

// The API container is the single source of the collab port it binds; absent it, there is none to reach.
if (apiContainer) boxServer.attachApi(apiContainer.app.fetch, apiContainer.collabPort);
await boxServer.start().catch((err) => logger.error('BOX_SERVER_START_FAILED', { err }));
// A co-editing session can sit open for hours between requests, so it is a pin, not a touch.
// Keyed off connections that cleared `onAuthenticate` (not BoxServer's pre-auth relay counter) -
// the ALB accepts /collab upgrades from anywhere with no WAF, so a pre-auth counter would let an
// unauthenticated upgrade hold the host (or a whole shared pool) awake indefinitely.
activityMonitor.addPin(() => apiContainer?.hasActiveCollabSession() ?? false);

if (!POOL_ID) {
  runtimeAttestation = await enableRuntimeAttestation(
    runtimeAttestation,
    logger.child({ component: 'attestation' }),
  );
  runtimeAttestation = await startRuntimeAttestation(
    runtimeAttestation,
    logger.child({ component: 'attestation' }),
  );
}
if (poolRuntimeAttestationServer && poolRuntimeAttestationListener) {
  await poolRuntimeAttestationServer.start(poolRuntimeAttestationListener);
  logger.info('pool runtime attestation listener started');
}

// One consumer serves every assigned tenant: it resolves each request's keyring/crypto from the
// message's own orgId (§4.2/§2.2), so wiki + theme synthesis run for the whole pool, not just N=1.
if (SYNTHESIS_REQUEST_QUEUE_URL) {
  synthesisConsumer = new SynthesisConsumer({
    sqs,
    s3,
    resolveTenant,
    processedBucket: PROCESSED_OUTPUTS_BUCKET,
    processedBucketFor: (orgId) => resolveTenant(orgId).processedOutputsBucket,
    synthesisQueueUrl: SYNTHESIS_REQUEST_QUEUE_URL,
    processedQueueUrl: PROCESSED_QUEUE_URL,
    previewFetcher: fetchLinkPreview,
    logger,
    outputAuthenticator,
    outputIdentity: () => ({
      deploymentId: OUTPUT_DEPLOYMENT_ID,
      assignmentGeneration: outputAssignmentGeneration(),
    }),
    isHaltedForTenant: async (tenantId) => {
      if (await poolHalt.isHalted()) return true;
      return new HaltGate(haltCache, tenantId, logger, [tenantHaltKey(tenantId)]).isHalted();
    },
  });
  synthesisConsumer.start();
}
// Synthesis runs off its own queue, invisible to the drain loop's idle check — and a job stopped
// halfway is lost work, so it holds the host up for as long as it takes.
activityMonitor.addPin(() => synthesisConsumer?.hasInFlightWork() ?? false);

async function writeIdleFlag(idle: boolean): Promise<void> {
  await ssm
    .send(
      new PutParameterCommand({
        Name: idleSsmPath,
        Value: idle ? '1' : '0',
        Type: 'String',
        Overwrite: true,
      }),
    )
    .catch((err) =>
      console.error('shutdown: non-fatal', {
        reason: err instanceof Error ? err.message : String(err),
      }),
    ); // non-fatal — parent timer will catch next cycle
}

const canaryAuthorizationConsumer =
  controlPlaneIdentity && controlPlaneFetch
    ? new HttpCanaryAuthorizationConsumer(
        controlPlaneIdentity.origin,
        DEPLOYMENT_ID,
        () => process.env['AGENT_TOKEN'] ?? '',
        controlPlaneFetch,
      )
    : undefined;

const router = new TenantMessageRouter({
  registry,
  ssm,
  s3,
  processedBucket: PROCESSED_OUTPUTS_BUCKET,
  controlPlaneUrl: controlPlaneIdentity?.origin ?? CONTROL_PLANE_URL,
  controlPlaneFetch:
    controlPlaneFetch ??
    (async () => {
      throw new Error('control_plane_identity_unavailable');
    }),
  deploymentId: DEPLOYMENT_ID,
  agentToken: () => process.env['AGENT_TOKEN'] ?? '',
  refreshOAuthCredential,
  jiraWebhookLifecycle,
  jiraWebhookAuthenticator,
  recordJiraWebhookDelivery,
  mintGitHubInstallationToken,
  canaryProofSigner: poolRuntimeAttestation
    ? {
        sign: (payload) => poolRuntimeAttestation.signCurrent(payload),
        sessionPublicKey: () => poolRuntimeAttestation.currentSessionPublicKey(),
      }
    : runtimeAttestation
      ? {
          sign: (payload) => runtimeAttestation!.signAssignmentAck(payload),
          sessionPublicKey: () => runtimeAttestation!.sessionPublicKey(),
        }
      : undefined,
  canaryProofSink,
  canaryAuthorizationConsumer,
});

// §2.2: write per-tenant pool usage to Redis after each drain cycle so the agent can
// read it on check-in (content-free: byte counts and opaque tenant ids only).
const collectPoolUsage = (): PoolTenantUsage[] =>
  registry.all().map((ctx) => ({
    tenant_id: ctx.tenantId,
    fact_count: ctx.hnsw.elementCount(),
    index_bytes: ctx.hnsw.indexBytes(),
    key_count: 1,
  }));

drainerRef.current = new QueueSetDrainer({
  sqs,
  s3,
  router,
  assignments: () => assignmentApplier.queueAssignments(),
  processedQueueUrl: PROCESSED_QUEUE_URL,
  processedOutputsBucket: PROCESSED_OUTPUTS_BUCKET,
  rawPayloadsBucket: RAW_PAYLOADS_BUCKET,
  outputAuthenticator,
  outputIdentity: (assignmentGeneration) => ({
    deploymentId: OUTPUT_DEPLOYMENT_ID,
    assignmentGeneration: assignmentGeneration ?? outputAssignmentGeneration(),
  }),
  poolHalt,
  haltGateFor: (tenantId) => new HaltGate(haltCache, tenantId, logger, [tenantHaltKey(tenantId)]),
  writeIdle: writeIdleFlag,
  idlePollThreshold: IDLE_POLL_THRESHOLD,
  isBusy: () => activityMonitor.isBusy(),
  onDrainComplete: async () => {
    if (!POOL_ID) return;
    await haltCache.set(`pool:usage:${DEPLOYMENT_ID}`, collectPoolUsage(), 300);
  },
  logger,
});

async function shutdown(): Promise<void> {
  logger.info('enclave shutting down — saving hnsw indices', { count: registry.size });
  clearInterval(assignmentRefreshTimer);
  tenantRequestQuiescence.stop();
  // Quiesce synthesis (await the in-flight op) and shred its theme indices + LLM-cache RAM fronts
  // before the final save, so no synth runs concurrently with it (§2.2 pt 5).
  if (synthesisConsumer)
    await synthesisConsumer.dispose(SHUTDOWN_QUIESCE_TIMEOUT_MS).catch((err) =>
      logger.error('shutdown: non-fatal', {
        reason: err instanceof Error ? err.message : String(err),
      }),
    );
  await runtimeAttestation?.close().catch((err) =>
    logger.error('shutdown: non-fatal', {
      reason: err instanceof Error ? err.message : String(err),
    }),
  );
  await poolRuntimeAttestationListener?.close().catch((err) =>
    logger.error('shutdown: non-fatal', {
      reason: err instanceof Error ? err.message : String(err),
    }),
  );
  await boxServer?.close().catch((err) =>
    logger.error('shutdown: non-fatal', {
      reason: err instanceof Error ? err.message : String(err),
    }),
  );
  await saveAllTenantIndices(registry.all(), s3, PROCESSED_OUTPUTS_BUCKET, logger);
  if (apiContainer)
    await apiContainer.close().catch((err) =>
      logger.error('shutdown: non-fatal', {
        reason: err instanceof Error ? err.message : String(err),
      }),
    );
  await haltCache.close().catch((err) =>
    logger.error('shutdown: non-fatal', {
      reason: err instanceof Error ? err.message : String(err),
    }),
  );
  resetMintedTokenCache();
  process.exit(0);
}

function createEnclaveOutputAuthenticator(): Ed25519EnclaveOutputAuthenticator {
  const key = verifiedBootManifest?.enclaveOutputKey;
  if (!key || !runtimeAttestation) {
    if (process.env['NODE_ENV'] === 'development') {
      return new Ed25519EnclaveOutputAuthenticator(DEVELOPMENT_ENCLAVE_OUTPUT_KEY);
    }
    throw new Error('enclave_output_signer_unavailable');
  }
  try {
    return new Ed25519EnclaveOutputAuthenticator({
      keyId: key.keyId,
      publicKeySpki: key.publicKeySpki,
      privateKeyPkcs8: runtimeAttestation.secretValue(key.privateKeySecretReferenceId),
    });
  } catch {
    throw new Error('enclave_output_signer_invalid');
  }
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());

void drainerRef.current.runForever();

function unavailableHighWaterTransport(): DurableGenerationHighWaterTransport {
  const unavailable = (): Promise<never> =>
    Promise.reject(new Error('high_water_transport_unavailable'));
  return {
    read: unavailable,
    commit: unavailable,
  };
}

function unavailableHighWaterVerifier(): DurableGenerationHighWaterVerifierPort {
  return {
    purpose: 'generation-high-water',
    verify: async () => {
      throw new Error('high_water_verifier_unavailable');
    },
  };
}
