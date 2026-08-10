import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { SQSClient } from '@aws-sdk/client-sqs';
import { SSMClient, PutParameterCommand, GetParameterCommand } from '@aws-sdk/client-ssm';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { awsClientTransport } from './aws/aws-transport.js';
import { TenantContextFactory } from './tenant/TenantContextFactory.js';
import { TenantRegistry } from './tenant/tenant-registry.js';
import {
  resolveBootAssignments,
  parseVersionedAssignmentManifest,
} from './tenant/tenant-assignments.js';
import { TenantAssignmentApplier } from './tenant/TenantAssignmentApplier.js';
import { TenantMessageRouter } from './tenant/tenant-message-router.js';
import { QueueSetDrainer } from './tenant/QueueSetDrainer.js';
import { saveAllTenantIndices } from './tenant/index-persistence.js';
import { createTenantResolver } from './tenant/tenant-resolver.js';
import { BoxServer } from './http/BoxServer.js';
import { SynthesisConsumer } from './workers/SynthesisConsumer.js';
import { fetchLinkPreview } from './preview/preview-client.js';
import { HaltGate } from './control/HaltGate.js';
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
  CRITIQUE_MODEL,
  EMBED_MODEL,
  GENERATE_MODEL,
  phalaInference,
  setInferenceTelemetry,
} from './inference/phala.js';
import {
  ANSWER_CACHE_VERSION,
  CachedInference,
  type InferenceModel,
} from './inference/CachedInference.js';
import { S3LlmCache } from './inference/S3LlmCache.js';
import { installGlobalEgressDispatcher } from './egress/proxy.js';
import { createContainer, type ApiContainer, type RetrieverDeps } from '@folklore/api';
import { NoopTelemetryClient } from '@folklore/telemetry';
import { RedisCache } from '@folklore/cache';
import { logger } from './logger.js';
import {
  BufferedOpsTelemetryClient,
  RedisOpsEventChannel,
  type PoolTenantUsage,
} from '@folklore/control-plane';
import {
  assignmentAckPayload,
  assignmentAckSchema,
  assignmentStorageProofPayload,
  poolAssignmentAckKey,
  poolAssignmentsKey,
  type SignedAssignmentManifest,
  versionedAssignmentManifestSchema,
} from '@folklore/contracts';
import { sha256Hex } from '@folklore/utils';
import {
  createRuntimeAttestationComposition,
  enableRuntimeAttestation,
  initializeRuntimeAttestationForBoot,
  startRuntimeAttestation,
} from './attestation/runtime-attestation-composition.js';
import type { VerifiedBootManifest } from './attestation/BootManifestVerifier.js';
import { createOAuthRuntime, createPinnedControlPlaneFetch } from './pull/oauth-composition.js';
import type { EnclaveOAuthIngress } from './pull/EnclaveOAuthIngress.js';
import { BootManifestSecretLoader } from './attestation/BootManifestSecretLoader.js';
import {
  AwsBootManifestSecretsManager,
  AwsBootManifestSsmParameters,
} from './attestation/boot-manifest-secret-clients.js';
import { getAttestationDoc } from './sealing/nsm.js';
import { deriveIngestKeypair } from './sealing/keygen.js';
import { devMasterKeySealers } from './sealing/dev-master-key-sealers.js';
import { StorageCanaryProof } from './tenant/StorageCanaryProof.js';
import {
  assignmentManifestPublicKeyForVerifiedBoot,
  verifyAssignmentManifest,
} from './tenant/VerifiedAssignmentManifest.js';

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
const AGENT_TOKEN_SSM_PATH = process.env['AGENT_TOKEN_SSM_PATH'] ?? '';
const OAUTH_PROVIDER_CONFIG_JSON = process.env['OAUTH_PROVIDER_CONFIG_JSON'] ?? '';
// Break-glass halt flag lives in the shared Redis, reached over the in-enclave
// vsock proxy. Required — the enclave refuses to boot without it (see below).
const REDIS_URL = process.env['REDIS_URL'] ?? '';
const ASSIGNMENT_MANIFEST_PUBLIC_KEY = process.env['ASSIGNMENT_MANIFEST_PUBLIC_KEY'] ?? '';

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
// Late-bound: the synthesis consumer and the answer-inference cache are composed further down, but
// the applier must be able to evict a torn-down tenant's resident theme index + LLM-cache RAM front
// the moment it drops it (§2.2 pt 5) - zeroize() only wipes the TenantContext's OWN handles, not a
// separately-held S3LlmCache/EnclaveCrypto reference this map captured earlier.
let synthesisConsumer: SynthesisConsumer | undefined;
let apiContainer: ApiContainer | undefined;
let evictAnswerInference: ((tenantId: string) => Promise<void>) | undefined;
const assignmentApplier = new TenantAssignmentApplier(
  registry,
  (identity) => tenantFactory.build(identity),
  logger,
  async (tenantId) => {
    const teardown = [
      synthesisConsumer?.evictTenant(tenantId),
      evictAnswerInference?.(tenantId),
    ].filter((result): result is Promise<void> => result !== undefined);
    const results = await Promise.allSettled(teardown);
    if (results.some((result) => result.status === 'rejected')) {
      throw new Error('tenant_subsystem_teardown_failed');
    }
  },
);
let runtimeAttestation =
  createRuntimeAttestationComposition({
    env: process.env,
    secretLoader: new BootManifestSecretLoader(
      new AwsBootManifestSecretsManager(secretsManager),
      new AwsBootManifestSsmParameters(ssm),
    ),
    nsm: { attest: getAttestationDoc },
    isTenantAssigned: () => registry.size > 0,
    isTenantApiReady: () => apiContainer !== undefined,
    getIngestPublicKey: () => {
      const context = registry.all()[0];
      return context ? deriveIngestKeypair(context.masterKey).publicKeyRaw : Uint8Array.from([]);
    },
    logger: logger.child({ component: 'attestation' }),
  }) ?? null;
runtimeAttestation = await initializeRuntimeAttestationForBoot(
  runtimeAttestation,
  async (prepared) => {
    verifiedBootManifest = prepared?.verifiedManifest();
    await assignmentApplier.apply(bootAssignments);
  },
  logger.child({ component: 'attestation' }),
);
console.log('tenant contexts assigned', { count: registry.size });

await loadInferenceKey();
assertInferenceConfigured();
await loadAgentToken();

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
  });
  oauthIngress = runtime.ingress;
  refreshOAuthCredential = runtime.refreshOAuthCredential;
  mintGitHubInstallationToken = runtime.mintGitHubInstallationToken;
}

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
const poolHalt = new HaltGate(haltCache, DEPLOYMENT_ID, logger);

// §4.3: the agent publishes this pool's content-free manifest to Redis on check-in; the enclave
// re-reads it and rebuilds the registry (add/remove tenants, §2.2 pt 5). Idempotent, so a periodic
// re-read reconverges to the latest assignment. Dedicated boxes have no POOL_ID and no manifest.
async function refreshAssignments(): Promise<void> {
  if (!POOL_ID) return;
  try {
    const manifest = await haltCache.get(poolAssignmentsKey(POOL_ID));
    if (!manifest) return;
    let parsed: SignedAssignmentManifest;
    try {
      parsed = parseVersionedAssignmentManifest(manifest, POOL_ID, assignmentApplier.generation());
    } catch (err) {
      if (!(err instanceof Error) || err.message !== 'assignment_manifest_stale') throw err;
      const replay = versionedAssignmentManifestSchema.parse(manifest);
      if (replay.poolId !== POOL_ID || !assignmentApplier.matchesCurrentManifest(replay)) throw err;
      parsed = replay;
    }
    const verified = verifyAssignmentManifest(
      parsed,
      assignmentManifestPublicKeyForVerifiedBoot(
        verifiedBootManifest,
        ASSIGNMENT_MANIFEST_PUBLIC_KEY,
      ),
    );
    const result = assignmentApplier.matchesCurrentManifest(verified)
      ? { applied: true as const, generation: parsed.generation }
      : await assignmentApplier.applyManifest(verified);
    if (!result.applied) return;
    if (!runtimeAttestation) throw new Error('runtime_attestation_not_ready');
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
    const signed = runtimeAttestation.signAssignmentAck(
      Buffer.from(assignmentAckPayload(unsignedAcknowledgment), 'utf8'),
    );
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
const opsTelemetry = new BufferedOpsTelemetryClient(
  new RedisOpsEventChannel(haltCache.redis, DEPLOYMENT_ID),
);
setInferenceTelemetry(opsTelemetry);

// Queue emptiness alone does not mean nobody is here: members read and edit through the box API,
// and synthesis runs long after its message is gone. This is what the drain loop's idle check
// consults so a self-stop can't land on a live session.
const activityMonitor = new ActivityMonitor({ quietWindowMs: ACTIVITY_QUIET_WINDOW_MS });

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
        embedModel: EMBED_MODEL,
        generateModel: GENERATE_MODEL,
        critiqueModel: CRITIQUE_MODEL,
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
  apiContainer = createContainer({
    // content-touching enclave opens no data-carrying egress — box-API telemetry inert by composition, not by omitting POSTHOG_API_KEY.
    telemetry: new NoopTelemetryClient(),
    // The box API serves reads for every assigned tenant; the verified JWT orgId must be in the
    // assigned set (else 403) — this gate runs before any handler touches a keyring (§4.2 step 2).
    isAssignedOrg: (orgId: string) => registry.has(orgId),
    // The API reports activity only from behind its own auth gate: /api/* takes unauthenticated
    // traffic from anywhere, and a scanner hitting it must not be able to hold this host awake.
    onAuthenticatedRequest: () => activityMonitor.touch(),
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
  });
  await apiContainer.start();
} catch (err) {
  // Degraded, not silent: the SPA still serves but /api/* returns 503 and /health reports
  // api:unavailable so the outage is observable, rather than a crash-looping boot.
  logger.error('BOX_API_DEGRADED', { err });
}

// The API container is the single source of the collab port it binds; absent it, there is none to reach.
// ENCLAVE_HTTP_PORT: dev-only override so the in-enclave box server can sit beside the standalone
// apps/api (same DEFAULT_HTTP_PORT) in a local `pnpm dev`; production keeps the default.
const boxServer = new BoxServer(apiContainer?.app.fetch, {
  httpPort: Number(process.env['ENCLAVE_HTTP_PORT'] ?? '') || undefined,
  collabPort: apiContainer?.collabPort,
  ...(oauthIngress ? { oauthIngress: oauthIngress.fetch } : {}),
});
await boxServer.start().catch((err) => logger.error('BOX_SERVER_START_FAILED', { err }));
// A co-editing session can sit open for hours between requests, so it is a pin, not a touch.
// Keyed off connections that cleared `onAuthenticate` (not BoxServer's pre-auth relay counter) -
// the ALB accepts /collab upgrades from anywhere with no WAF, so a pre-auth counter would let an
// unauthenticated upgrade hold the host (or a whole shared pool) awake indefinitely.
activityMonitor.addPin(() => apiContainer?.hasActiveCollabSession() ?? false);

runtimeAttestation = await enableRuntimeAttestation(
  runtimeAttestation,
  logger.child({ component: 'attestation' }),
);
runtimeAttestation = await startRuntimeAttestation(
  runtimeAttestation,
  logger.child({ component: 'attestation' }),
);

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
  mintGitHubInstallationToken,
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

const drainer = new QueueSetDrainer({
  sqs,
  s3,
  router,
  assignments: () => assignmentApplier.queueAssignments(),
  processedQueueUrl: PROCESSED_QUEUE_URL,
  processedOutputsBucket: PROCESSED_OUTPUTS_BUCKET,
  rawPayloadsBucket: RAW_PAYLOADS_BUCKET,
  poolHalt,
  haltGateFor: (tenantId) => new HaltGate(haltCache, tenantId, logger),
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
  await boxServer.close().catch((err) =>
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
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());

void drainer.runForever();
