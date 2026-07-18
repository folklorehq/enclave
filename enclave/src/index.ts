import { S3Client } from '@aws-sdk/client-s3';
import { SQSClient } from '@aws-sdk/client-sqs';
import { SSMClient, PutParameterCommand, GetParameterCommand } from '@aws-sdk/client-ssm';
import { TenantContextFactory } from './tenant/tenant-context-factory.js';
import { TenantRegistry } from './tenant/tenant-registry.js';
import { resolveBootAssignments, parseAssignmentManifest } from './tenant/tenant-assignments.js';
import { TenantAssignmentApplier } from './tenant/tenant-assignment-applier.js';
import { TenantMessageRouter } from './tenant/tenant-message-router.js';
import { QueueSetDrainer } from './tenant/queue-set-drainer.js';
import { saveAllTenantIndices } from './tenant/index-persistence.js';
import { createTenantResolver } from './tenant/tenant-resolver.js';
import { BoxServer } from './http/server.js';
import { SynthesisConsumer } from './workers/synthesis-consumer.js';
import { fetchLinkPreview } from './preview/preview-client.js';
import { HaltGate } from './control/halt-gate.js';
import { EnclaveFactRetriever } from './retrieval/fact-retriever.js';
import { EnclaveFactAnswerer } from './workers/fact-answerer.js';
import { EnclaveWikiContentDecryptor } from './wiki/content-decryptor.js';
import { EnclaveWikiEditSealer } from './wiki/edit-sealer.js';
import {
  EnclaveWikiCommentSealer,
  EnclaveWikiFeedbackSealer,
  EnclaveWikiSnapshotSealer,
} from './wiki/content-sealers.js';
import {
  assertInferenceConfigured,
  EMBED_MODEL,
  GENERATE_MODEL,
  phalaInference,
  setInferenceTelemetry,
} from './inference/phala.js';
import {
  CachedInference,
  LLM_CACHE_PROMPT_VERSION,
  type InferenceModel,
} from './inference/cached-inference.js';
import { S3LlmCache } from './inference/s3-llm-cache.js';
import { installGlobalEgressDispatcher } from './egress/proxy.js';
import { createContainer, type ApiContainer, type RetrieverDeps } from '@folklore/api';
import { NoopTelemetryClient } from '@folklore/telemetry';
import { RedisCache } from '@folklore/cache';
import { BufferedOpsTelemetryClient, RedisOpsEventChannel } from '@folklore/control-plane';
import { poolAssignmentsKey } from '@folklore/contracts';

// ADL #42: route external egress through the parent CONNECT proxy — before any client is
// built, so undici SDKs pick up the dispatcher (loopback bypasses it, keeping AWS/inference).
installGlobalEgressDispatcher();

const REGION = process.env['AWS_REGION']!;
const SEALED_BLOB_BUCKET = process.env['SEALED_BLOB_BUCKET']!;
const PROCESSED_OUTPUTS_BUCKET = process.env['PROCESSED_OUTPUTS_BUCKET']!;
const PROCESSED_QUEUE_URL = process.env['PROCESSED_QUEUE_URL']!;
const RAW_PAYLOADS_BUCKET = process.env['RAW_PAYLOADS_BUCKET'] ?? '';
const SYNTHESIS_REQUEST_QUEUE_URL = process.env['SYNTHESIS_REQUEST_QUEUE_URL'] ?? '';
const TEE_API_KEY_SSM_PATH = process.env['TEE_API_KEY_SSM_PATH'] ?? '';
const PROXY_PORT = process.env['VSOCK_KMS_PROXY_PORT'] ?? '8000';
// ADL #42: pull transports run in-enclave. The control plane only ever hands back
// ciphertext (source OAuth tokens ECIES-encrypted to this enclave's public key);
// this shared deployment secret (the same one `apps/agent` uses to check in) is
// what authenticates the enclave's fetch of those encrypted connections.
const CONTROL_PLANE_URL = process.env['CONTROL_PLANE_URL'] ?? '';
const DEPLOYMENT_ID = process.env['DEPLOYMENT_ID'] ?? '';
const AGENT_TOKEN_SSM_PATH = process.env['AGENT_TOKEN_SSM_PATH'] ?? '';
// Break-glass halt flag lives in the shared Redis, reached over the in-enclave
// vsock proxy (ADL #13, #31). Required — the enclave refuses to boot without it (see below).
const REDIS_URL = process.env['REDIS_URL'] ?? '';

// After 15 consecutive empty long-polls (~5 min) across ALL assigned queues the enclave signals idle.
const IDLE_POLL_THRESHOLD = 15;

// vsock proxy on the parent EC2 routes all AWS SDK calls without internet egress
const proxyEndpoint = `https://localhost:${PROXY_PORT}`;

const s3 = new S3Client({ region: REGION, endpoint: proxyEndpoint });
const sqs = new SQSClient({ region: REGION, endpoint: proxyEndpoint });
const ssm = new SSMClient({ region: REGION, endpoint: proxyEndpoint });

async function loadInferenceKey(): Promise<void> {
  if (!TEE_API_KEY_SSM_PATH || process.env['TEE_API_KEY']) return;
  try {
    const resp = await ssm.send(
      new GetParameterCommand({ Name: TEE_API_KEY_SSM_PATH, WithDecryption: true }),
    );
    if (resp.Parameter?.Value) process.env['TEE_API_KEY'] = resp.Parameter.Value;
  } catch (err) {
    console.error('failed to load inference key from SSM', { err });
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
    console.error('failed to load agent token from SSM', { err });
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

const tenantFactory = new TenantContextFactory({
  s3,
  ssm,
  region: REGION,
  proxyEndpoint,
  sealedBlobBucket: SEALED_BLOB_BUCKET,
  processedOutputsBucket: PROCESSED_OUTPUTS_BUCKET,
});
const registry = new TenantRegistry();
// Late-bound: the synthesis consumer is composed further down, but the applier must be able to evict
// a torn-down tenant's resident theme index + LLM-cache RAM front the moment it drops it (§2.2 pt 5).
let synthesisConsumer: SynthesisConsumer | undefined;
const assignmentApplier = new TenantAssignmentApplier(
  registry,
  (identity) => tenantFactory.build(identity),
  (tenantId) => synthesisConsumer?.evictTenant(tenantId),
);
await assignmentApplier.apply(bootAssignments);
console.log('tenant contexts assigned', { count: registry.size });

await loadInferenceKey();
assertInferenceConfigured();
await loadAgentToken();

// Per-request keyring selection from the verified JWT orgId (design §4.2): every read/synthesis
// path resolves its TenantContext through this one choke point, which fails closed (403) on an
// orgId not in the assigned set BEFORE any keyring is reachable. No single boot-time "box context".
const resolveTenant = createTenantResolver(registry);

// ADL #13: the break-glass halt and billing suspension gate every dequeue. Without a
// halt gate the loop would drain/decrypt fail-open, so refuse to boot rather than run ungated.
if (!DEPLOYMENT_ID || !REDIS_URL) {
  throw new Error(
    'refusing to start: halt gate unavailable (DEPLOYMENT_ID and REDIS_URL required)',
  );
}
const haltCache = new RedisCache(REDIS_URL);
// Pool-wide emergency halt (unchanged single-tenant semantics); per-tenant gates are built on demand
// (§6.3) since the assigned set changes live, so halting tenant A never stops tenant B's queue.
const poolHalt = new HaltGate(haltCache, DEPLOYMENT_ID);

// §4.3: the agent publishes this pool's content-free manifest to Redis on check-in; the enclave
// re-reads it and rebuilds the registry (add/remove tenants, §2.2 pt 5). Idempotent, so a periodic
// re-read reconverges to the latest assignment. Dedicated boxes have no POOL_ID and no manifest.
async function refreshAssignments(): Promise<void> {
  if (!POOL_ID) return;
  try {
    const manifest = await haltCache.get(poolAssignmentsKey(POOL_ID));
    if (!manifest) return;
    await assignmentApplier.apply(parseAssignmentManifest(manifest, POOL_ID));
  } catch (err) {
    // Log the error NAME only, never the raw error (ADL #18 — a message could echo a manifest field).
    // A bad/foreign manifest leaves the current assignment set untouched — fail closed, don't tear
    // down live tenants on a parse slip.
    console.error('assignment manifest refresh failed', {
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

// ADL #18: the enclave has no PostHog egress, so ops telemetry (attestation failures, receipt
// verifications, model-gate rejections) is buffered onto the shared Redis list the box agent
// drains into its content-free check-in.
const opsTelemetry = new BufferedOpsTelemetryClient(
  new RedisOpsEventChannel(haltCache.redis, DEPLOYMENT_ID),
);
setInferenceTelemetry(opsTelemetry);

// ADL #31: the box API is composed and served in-process. Every /api/* request
// reads decrypted content over the in-enclave Postgres proxy and never leaves.
let apiContainer: ApiContainer | undefined;
try {
  // ADL #34/#6: search + wiki/recommend are served by the in-enclave retriever — embed, ANN over
  // the loaded index, decrypt, and audience-gate, all in-process. The retriever resolves its
  // tenant's index + keyring per request from `params.orgId` (§4.2), so it serves every assigned
  // tenant from one instance without a union keyring.
  const buildRetriever = (retrieverDeps: RetrieverDeps) =>
    new EnclaveFactRetriever({
      ...retrieverDeps,
      resolveTenant,
      s3,
      processedBucket: PROCESSED_OUTPUTS_BUCKET,
    });
  // Content-addressed, ESDK-sealed per-org LLM cache in front of phala (determinism #1, ADL #12):
  // a repeated question over an unchanged fact set replays without a fresh TEE call. Resolved PER
  // REQUEST from the answer's orgId (§4.2) — never a boot-time context — so the cache blob is sealed
  // and read under the requesting tenant's own key/orgId AAD and can't cross tenants. Memoized per
  // org (each entry uses only that tenant's crypto), mirroring the synthesis workers' cache.
  const answerInferenceByOrg = new Map<string, InferenceModel>();
  const answerInferenceFor = (orgId: string): InferenceModel => {
    let inference = answerInferenceByOrg.get(orgId);
    if (!inference) {
      const tenant = resolveTenant(orgId); // fail-closed (403) on an unassigned org before any keyring
      inference = new CachedInference(
        phalaInference,
        new S3LlmCache({ s3, crypto: tenant.crypto, bucket: PROCESSED_OUTPUTS_BUCKET, orgId }),
        {
          embedModel: EMBED_MODEL,
          generateModel: GENERATE_MODEL,
          promptVersion: LLM_CACHE_PROMPT_VERSION,
        },
      );
      answerInferenceByOrg.set(orgId, inference);
    }
    return inference;
  };
  apiContainer = createContainer({
    // ADL #18/#35: content-touching enclave opens no data-carrying egress — box-API telemetry inert by composition, not by omitting POSTHOG_API_KEY.
    telemetry: new NoopTelemetryClient(),
    // The box API serves reads for every assigned tenant; the verified JWT orgId must be in the
    // assigned set (else 403) — this gate runs before any handler touches a keyring (§4.2 step 2).
    isAssignedOrg: (orgId: string) => registry.has(orgId),
    retrieverFactory: buildRetriever,
    // ADL #34/#27: grounded answers reuse the same per-request gated retrieval spine, then feed only
    // audience-visible decrypted bodies to the in-enclave TEE model — nothing leaves the enclave.
    // `generate` is stateless (no per-org seal), so the answer path is per-request via the retriever.
    answerServiceFactory: (retrieverDeps) =>
      new EnclaveFactAnswerer(buildRetriever(retrieverDeps), (orgId, prompt, systemPrompt) =>
        answerInferenceFor(orgId).generate(prompt, systemPrompt),
      ),
    // ADL #12: synthesized wiki text is ciphertext at rest; the read path decrypts audience-visible
    // blocks here, in-enclave, over the requesting tenant's sealed key (resolved from `ref.orgId`).
    wikiContentDecryptor: new EnclaveWikiContentDecryptor(resolveTenant),
    // ADL #12/#45: mined draft→edit prose is sealed to the requesting tenant's key, in-enclave only.
    wikiEditSealer: new EnclaveWikiEditSealer(resolveTenant),
    // ADL #12: live-collab Yjs snapshots, comments, and feedback corrections are sealed to the
    // requesting tenant's key, in-enclave only.
    wikiSnapshotSealer: new EnclaveWikiSnapshotSealer(resolveTenant),
    wikiCommentSealer: new EnclaveWikiCommentSealer(resolveTenant),
    wikiFeedbackSealer: new EnclaveWikiFeedbackSealer(resolveTenant),
  });
  await apiContainer.start();
} catch (err) {
  // Degraded, not silent: the SPA still serves but /api/* returns 503 and /health reports
  // api:unavailable so the outage is observable, rather than a crash-looping boot.
  console.error('BOX_API_DEGRADED', { err });
}

new BoxServer(apiContainer?.app.fetch).start();

// One consumer serves every assigned tenant: it resolves each request's keyring/crypto from the
// message's own orgId (§4.2/§2.2), so wiki + theme synthesis run for the whole pool, not just N=1.
if (SYNTHESIS_REQUEST_QUEUE_URL) {
  synthesisConsumer = new SynthesisConsumer({
    sqs,
    s3,
    resolveTenant,
    processedBucket: PROCESSED_OUTPUTS_BUCKET,
    synthesisQueueUrl: SYNTHESIS_REQUEST_QUEUE_URL,
    processedQueueUrl: PROCESSED_QUEUE_URL,
    previewFetcher: fetchLinkPreview,
  });
  synthesisConsumer.start();
}

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
    .catch(() => {}); // non-fatal — parent timer will catch next cycle
}

const router = new TenantMessageRouter({
  registry,
  ssm,
  controlPlaneUrl: CONTROL_PLANE_URL,
  deploymentId: DEPLOYMENT_ID,
  agentToken: () => process.env['AGENT_TOKEN'] ?? '',
});

const drainer = new QueueSetDrainer({
  sqs,
  s3,
  router,
  assignments: () => assignmentApplier.queueAssignments(),
  processedQueueUrl: PROCESSED_QUEUE_URL,
  processedOutputsBucket: PROCESSED_OUTPUTS_BUCKET,
  rawPayloadsBucket: RAW_PAYLOADS_BUCKET,
  poolHalt,
  haltGateFor: (tenantId) => new HaltGate(haltCache, tenantId),
  writeIdle: writeIdleFlag,
  idlePollThreshold: IDLE_POLL_THRESHOLD,
});

async function shutdown(): Promise<void> {
  console.log('enclave shutting down — saving hnsw indices', { count: registry.size });
  clearInterval(assignmentRefreshTimer);
  // Quiesce synthesis (await the in-flight op) and shred its theme indices + LLM-cache RAM fronts
  // before the final save, so no synth runs concurrently with it (§2.2 pt 5).
  if (synthesisConsumer)
    await synthesisConsumer.dispose(SHUTDOWN_QUIESCE_TIMEOUT_MS).catch(() => {});
  await saveAllTenantIndices(registry.all(), s3, PROCESSED_OUTPUTS_BUCKET);
  if (apiContainer) await apiContainer.close().catch(() => {});
  await haltCache.close().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());

void drainer.runForever();
