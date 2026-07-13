import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import {
  SQSClient,
  ReceiveMessageCommand,
  DeleteMessageCommand,
  SendMessageCommand,
} from '@aws-sdk/client-sqs';
import { SSMClient, PutParameterCommand, GetParameterCommand } from '@aws-sdk/client-ssm';
import { decryptPayload, type EncryptedPayload } from './ingest/receiver.js';
import { TenantContextFactory } from './tenant/tenant-context-factory.js';
import { TenantRegistry } from './tenant/tenant-registry.js';
import { BoxServer } from './http/server.js';
import { SynthesisConsumer } from './workers/synthesis-consumer.js';
import { fetchLinkPreview } from './preview/preview-client.js';
import { runPull, buildPullCompleteSignal, type PullDueMessage } from './pull/pull-runner.js';
import { HaltGate, HALT_POLL_INTERVAL_MS } from './control/halt-gate.js';
import { EnclaveFactRetriever } from './retrieval/fact-retriever.js';
import { EnclaveWikiContentDecryptor } from './wiki/content-decryptor.js';
import { EnclaveWikiEditSealer } from './wiki/edit-sealer.js';
import {
  EnclaveWikiCommentSealer,
  EnclaveWikiFeedbackSealer,
  EnclaveWikiSnapshotSealer,
} from './wiki/content-sealers.js';
import { assertInferenceConfigured, setInferenceTelemetry } from './inference/phala.js';
import { installGlobalEgressDispatcher } from './egress/proxy.js';
import { createContainer, type ApiContainer } from '@folklore/api';
import { RedisCache } from '@folklore/cache';
import { BufferedOpsTelemetryClient, RedisOpsEventChannel } from '@folklore/control-plane';

// ADL #42: route external egress through the parent CONNECT proxy — before any client is
// built, so undici SDKs pick up the dispatcher (loopback bypasses it, keeping AWS/inference).
installGlobalEgressDispatcher();

const REGION = process.env['AWS_REGION']!;
const TENANT_ID = process.env['TENANT_ID']!;
const KMS_KEY_ID = process.env['KMS_KEY_ID']!;
const SEALED_BLOB_BUCKET = process.env['SEALED_BLOB_BUCKET']!;
const QUEUE_URL = process.env['QUEUE_URL']!;
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
// ADL #55: customer's X25519 recovery public key (hex, content-free/public). First boot
// refuses to generate a master key without it — no tenant may hold data with zero recovery path.
const RECOVERY_PUBKEY = process.env['RECOVERY_PUBKEY'] ?? '';

const IDLE_SSM_PATH = `/folklore/${TENANT_ID}/idle`;
// After 15 consecutive empty long-polls (~5 min) the enclave signals idle.
const IDLE_POLL_THRESHOLD = 15;

// vsock proxy on the parent EC2 routes all AWS SDK calls without internet egress
const proxyEndpoint = `https://localhost:${PROXY_PORT}`;

const s3 = new S3Client({ region: REGION, endpoint: proxyEndpoint });
const sqs = new SQSClient({ region: REGION, endpoint: proxyEndpoint });
const ssm = new SSMClient({ region: REGION, endpoint: proxyEndpoint });

interface SqsMessage {
  tenant_id: string;
  source: string;
  eventType?: string;
  type?: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

function isPullDueMessage(raw: { type?: string }): raw is PullDueMessage {
  return raw.type === 'pull-due';
}

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

async function processLoop(
  registry: TenantRegistry,
  assignedTenantId: string,
  haltGate: HaltGate,
): Promise<void> {
  console.log('processing loop started', { queue: QUEUE_URL });

  let idlePolls = 0;
  let isIdle = false;

  const drainBatch = async (): Promise<void> => {
    const resp = await sqs.send(
      new ReceiveMessageCommand({
        QueueUrl: QUEUE_URL,
        MaxNumberOfMessages: 10,
        WaitTimeSeconds: 20,
      }),
    );

    const messages = resp.Messages ?? [];

    if (messages.length === 0) {
      idlePolls++;
      if (idlePolls >= IDLE_POLL_THRESHOLD && !isIdle) {
        isIdle = true;
        await ssm
          .send(
            new PutParameterCommand({
              Name: IDLE_SSM_PATH,
              Value: '1',
              Type: 'String',
              Overwrite: true,
            }),
          )
          .catch(() => {}); // non-fatal — parent timer will catch next cycle
      }
    } else {
      if (isIdle) {
        isIdle = false;
        await ssm
          .send(
            new PutParameterCommand({
              Name: IDLE_SSM_PATH,
              Value: '0',
              Type: 'String',
              Overwrite: true,
            }),
          )
          .catch(() => {});
      }
      idlePolls = 0;
    }

    for (const msg of messages) {
      if (RAW_PAYLOADS_BUCKET && msg.MessageId && msg.Body) {
        const now = new Date();
        const archiveKey = `${assignedTenantId}/${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, '0')}/${String(now.getUTCDate()).padStart(2, '0')}/${msg.MessageId}`;
        void s3
          .send(
            new PutObjectCommand({
              Bucket: RAW_PAYLOADS_BUCKET,
              Key: archiveKey,
              Body: msg.Body,
              ContentType: 'text/plain',
            }),
          )
          .catch(() => {});
      }
      try {
        const raw = JSON.parse(msg.Body!) as SqsMessage | PullDueMessage;
        // Every keyed op takes its tenant from an explicit context, never a process-global
        // (design §2.2/§2.3). An unassigned tenant_id throws here and the message is left in
        // queue — it is undecryptable under any assigned key anyway.
        const context = registry.get(raw.tenant_id);
        const facts = isPullDueMessage(raw)
          ? await runPull(raw, {
              ssm,
              privateKey: context.ingestPrivateKey,
              controlPlaneUrl: CONTROL_PLANE_URL,
              deploymentId: DEPLOYMENT_ID,
              agentToken: process.env['AGENT_TOKEN'] ?? '',
              pipeline: context.pipeline,
            })
          : await (async () => {
              const encryptedPayload: EncryptedPayload = {
                ephemeralPublicKey: raw.ephemeralPublicKey,
                nonce: raw.nonce,
                ciphertext: raw.ciphertext,
              };
              const plaintext = decryptPayload(encryptedPayload, context.ingestPrivateKey);
              return raw.type === 'pull-normalized'
                ? context.pipeline.handleNormalized(plaintext, raw.source)
                : context.pipeline.handle(plaintext, raw.source, raw.eventType ?? '');
            })();
        for (const fact of facts) {
          await sqs.send(
            new SendMessageCommand({
              QueueUrl: PROCESSED_QUEUE_URL,
              MessageBody: JSON.stringify(fact),
              MessageGroupId: fact.orgId,
              MessageDeduplicationId: fact.factId,
            }),
          );
        }
        // A completed pull (even one that yielded no new facts) advances sync health so the
        // scheduler's staleness-based recovery backfill works (ADL #38); worker owns the DB write.
        if (isPullDueMessage(raw)) {
          const signal = buildPullCompleteSignal(raw);
          await sqs.send(
            new SendMessageCommand({
              QueueUrl: PROCESSED_QUEUE_URL,
              MessageBody: JSON.stringify(signal),
              MessageGroupId: signal.orgId,
              MessageDeduplicationId: `pull-complete-${signal.sourceId}-${signal.completedAt}`,
            }),
          );
        }
        await sqs.send(
          new DeleteMessageCommand({ QueueUrl: QUEUE_URL, ReceiptHandle: msg.ReceiptHandle! }),
        );
      } catch {
        // Content-free SQS id only — err could carry a decrypted-content snippet (ADL #18).
        console.error('failed to process message', { id: msg.MessageId });
        // Leave in queue — visibility timeout retries, DLQ after 3 attempts
      }
    }
  };

  for (;;) {
    // Gate before any dequeue: a halted box must not receive, decrypt, or
    // persist. When halted, idle without touching the queue and re-check.
    const processed = await haltGate.guard(drainBatch);
    if (!processed) await new Promise((resolve) => setTimeout(resolve, HALT_POLL_INTERVAL_MS));
  }
}

// Stage 1 (shared-tier design §9): the registry holds exactly ONE context, built from
// TENANT_ID/KMS_KEY_ID. This replaces the former process-global keyring/masterKey/hnsw/pipeline
// so Stage 2 can build N contexts without any tenant sharing a keyring — pure refactor for now.
const tenantFactory = new TenantContextFactory({
  s3,
  ssm,
  region: REGION,
  proxyEndpoint,
  sealedBlobBucket: SEALED_BLOB_BUCKET,
  processedOutputsBucket: PROCESSED_OUTPUTS_BUCKET,
});
const registry = new TenantRegistry();
registry.register(
  await tenantFactory.build({
    tenantId: TENANT_ID,
    kmsKeyId: KMS_KEY_ID,
    recoveryPubkey: RECOVERY_PUBKEY,
  }),
);
await loadInferenceKey();
assertInferenceConfigured();
await loadAgentToken();

// Stage 1 keeps single-context read-path wiring, but sourced from the registry rather than a bare
// global; Stage 2 resolves the context per request from the verified JWT orgId (design §4.2).
const boxContext = registry.get(TENANT_ID);

// ADL #13: the break-glass halt and billing suspension gate every dequeue. Without a
// halt gate the loop would drain/decrypt fail-open, so refuse to boot rather than run ungated.
if (!DEPLOYMENT_ID || !REDIS_URL) {
  throw new Error(
    'refusing to start: halt gate unavailable (DEPLOYMENT_ID and REDIS_URL required)',
  );
}
const haltCache = new RedisCache(REDIS_URL);
const haltGate = new HaltGate(haltCache, DEPLOYMENT_ID);

// ADL #18: the enclave has no PostHog egress, so inference ops telemetry (attestation
// failures, receipt verifications, model-gate rejections) is buffered onto the shared
// Redis list the box agent drains into its content-free check-in.
setInferenceTelemetry(
  new BufferedOpsTelemetryClient(new RedisOpsEventChannel(haltCache.redis, DEPLOYMENT_ID)),
);

// ADL #31: the box API is composed and served in-process. Every /api/* request
// reads decrypted content over the in-enclave Postgres proxy and never leaves.
let apiContainer: ApiContainer | undefined;
try {
  // ADL #34/#6: search + wiki/recommend are served by the in-enclave retriever —
  // embed, ANN over the loaded index, decrypt, and audience-gate, all in-process.
  apiContainer = createContainer({
    retrieverFactory: (retrieverDeps) =>
      new EnclaveFactRetriever({
        ...retrieverDeps,
        hnsw: boxContext.hnsw,
        s3,
        keyring: boxContext.keyring,
        processedBucket: PROCESSED_OUTPUTS_BUCKET,
      }),
    // ADL #12: synthesized wiki text is ciphertext at rest; the read path decrypts
    // audience-visible blocks here, in-enclave, over the sealed key.
    wikiContentDecryptor: new EnclaveWikiContentDecryptor(boxContext.keyring),
    // ADL #12/#45: mined draft→edit prose is sealed to the same key, in-enclave only.
    wikiEditSealer: new EnclaveWikiEditSealer(boxContext.keyring),
    // ADL #12: live-collab Yjs snapshots, comments, and feedback corrections are sealed to the
    // same key, in-enclave only.
    wikiSnapshotSealer: new EnclaveWikiSnapshotSealer(boxContext.keyring),
    wikiCommentSealer: new EnclaveWikiCommentSealer(boxContext.keyring),
    wikiFeedbackSealer: new EnclaveWikiFeedbackSealer(boxContext.keyring),
  });
  await apiContainer.start();
} catch (err) {
  // Degraded, not silent: the SPA still serves but /api/* returns 503 and /health
  // reports api:unavailable so the outage is observable instead of looking healthy.
  console.error('BOX_API_DEGRADED', { reason: 'container failed to start', err });
}

new BoxServer(apiContainer?.app.fetch).start();

if (SYNTHESIS_REQUEST_QUEUE_URL) {
  // One consumer handles both wiki and theme synthesis requests (dispatched by `type`).
  new SynthesisConsumer({
    sqs,
    s3,
    keyring: boxContext.keyring,
    processedBucket: PROCESSED_OUTPUTS_BUCKET,
    synthesisQueueUrl: SYNTHESIS_REQUEST_QUEUE_URL,
    processedQueueUrl: PROCESSED_QUEUE_URL,
    previewFetcher: fetchLinkPreview,
  }).start();
}

async function shutdown(): Promise<void> {
  console.log('enclave shutting down — saving hnsw index');
  await boxContext.hnsw.save(s3, boxContext.keyring, PROCESSED_OUTPUTS_BUCKET, TENANT_ID);
  if (apiContainer) await apiContainer.close().catch(() => {});
  await haltCache.close().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());

void processLoop(registry, TENANT_ID, haltGate);
