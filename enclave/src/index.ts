import { S3Client, GetObjectCommand, PutObjectCommand, NoSuchKey } from '@aws-sdk/client-s3';
import {
  SQSClient,
  ReceiveMessageCommand,
  DeleteMessageCommand,
  SendMessageCommand,
} from '@aws-sdk/client-sqs';
import { SSMClient, PutParameterCommand, GetParameterCommand } from '@aws-sdk/client-ssm';
import { KMSClient } from '@aws-sdk/client-kms';
import { KmsKeyringNode } from '@aws-crypto/client-node';
import { generateMasterKey, deriveIngestKeypair } from './sealing/keygen.js';
import { sealMasterKey, unsealMasterKey } from './sealing/seal.js';
import { assertRecoveryConfigured, sealRecoveryMnemonic } from './sealing/recovery.js';
import { decryptPayload, type EncryptedPayload } from './ingest/receiver.js';
import { Pipeline } from './pipeline/index.js';
import { HnswStore } from './hnsw/index.js';
import { BoxServer } from './http/server.js';
import { SynthesisConsumer } from './workers/synthesis-consumer.js';
import { fetchLinkPreview } from './preview/preview-client.js';
import { runPull, buildPullCompleteSignal, type PullDueMessage } from './pull/pull-runner.js';
import { HaltGate, HALT_POLL_INTERVAL_MS } from './control/halt-gate.js';
import { EnclaveFactRetriever } from './retrieval/fact-retriever.js';
import { EnclaveWikiContentDecryptor } from './wiki/content-decryptor.js';
import { EnclaveWikiEditSealer } from './wiki/edit-sealer.js';
import { assertInferenceConfigured, setInferenceTelemetry } from './inference/phala.js';
import { createContainer, type ApiContainer } from '@folklore/api';
import { RedisCache } from '@folklore/cache';
import { BufferedOpsTelemetryClient, RedisOpsEventChannel } from '@folklore/control-plane';

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

const SEALED_BLOB_KEY = `sealed-keys/${TENANT_ID}/master.blob`;
const RECOVERY_BLOB_KEY = `recovery/${TENANT_ID}/mnemonic.enc`;
const INGEST_KEY_SSM_PATH = `/folklore/${TENANT_ID}/ingest-public-key`;
const IDLE_SSM_PATH = `/folklore/${TENANT_ID}/idle`;
// After 15 consecutive empty long-polls (~5 min) the enclave signals idle.
const IDLE_POLL_THRESHOLD = 15;

// vsock proxy on the parent EC2 routes all AWS SDK calls without internet egress
const proxyEndpoint = `https://localhost:${PROXY_PORT}`;

const s3 = new S3Client({ region: REGION, endpoint: proxyEndpoint });
const sqs = new SQSClient({ region: REGION, endpoint: proxyEndpoint });
const ssm = new SSMClient({ region: REGION, endpoint: proxyEndpoint });

const keyring = new KmsKeyringNode({
  generatorKeyId: KMS_KEY_ID,
  clientProvider: (r?: string) =>
    new KMSClient({ region: r ?? REGION, endpoint: proxyEndpoint }) as never,
});

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

async function boot(): Promise<Buffer> {
  let sealedBlob: Buffer | null = null;

  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: SEALED_BLOB_BUCKET, Key: SEALED_BLOB_KEY }),
    );
    sealedBlob = Buffer.from(await obj.Body!.transformToByteArray());
  } catch (err) {
    if (!(err instanceof NoSuchKey)) throw err;
  }

  if (sealedBlob) {
    console.log('unsealing master key via KMS');
    const masterKey = await unsealMasterKey(sealedBlob, KMS_KEY_ID);
    console.log('unseal ok');
    return masterKey;
  }

  console.log('first boot — generating master key');
  // Fail closed before generating a key we could never let the customer recover (ADL #55).
  const recoveryKey = assertRecoveryConfigured(RECOVERY_PUBKEY);
  const masterKey = generateMasterKey();

  // Store only ciphertext the customer alone can open; write it before persisting the
  // master blob so a recovery-store failure leaves no ingestible tenant behind.
  const recoveryBox = sealRecoveryMnemonic(masterKey, recoveryKey);
  await s3.send(
    new PutObjectCommand({
      Bucket: SEALED_BLOB_BUCKET,
      Key: RECOVERY_BLOB_KEY,
      Body: JSON.stringify(recoveryBox),
      ContentType: 'application/json',
    }),
  );

  const blob = await sealMasterKey(masterKey, KMS_KEY_ID);
  await s3.send(
    new PutObjectCommand({ Bucket: SEALED_BLOB_BUCKET, Key: SEALED_BLOB_KEY, Body: blob }),
  );

  const { publicKeyRaw } = deriveIngestKeypair(masterKey);
  await ssm.send(
    new PutParameterCommand({
      Name: INGEST_KEY_SSM_PATH,
      Value: publicKeyRaw.toString('hex'),
      Type: 'String',
      Overwrite: true,
    }),
  );

  console.log('FIRST_BOOT', { tenant: TENANT_ID });
  return masterKey;
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
  masterKey: Buffer,
  pipeline: Pipeline,
  haltGate: HaltGate,
): Promise<void> {
  const { privateKey } = deriveIngestKeypair(masterKey);
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
        const archiveKey = `${TENANT_ID}/${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, '0')}/${String(now.getUTCDate()).padStart(2, '0')}/${msg.MessageId}`;
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
        const facts = isPullDueMessage(raw)
          ? await runPull(raw, {
              ssm,
              privateKey,
              controlPlaneUrl: CONTROL_PLANE_URL,
              deploymentId: DEPLOYMENT_ID,
              agentToken: process.env['AGENT_TOKEN'] ?? '',
              pipeline,
            })
          : await (async () => {
              const encryptedPayload: EncryptedPayload = {
                ephemeralPublicKey: raw.ephemeralPublicKey,
                nonce: raw.nonce,
                ciphertext: raw.ciphertext,
              };
              const plaintext = decryptPayload(encryptedPayload, privateKey);
              return raw.type === 'pull-normalized'
                ? pipeline.handleNormalized(plaintext, raw.source)
                : pipeline.handle(plaintext, raw.source, raw.eventType ?? '');
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

const masterKey = await boot();
await loadInferenceKey();
assertInferenceConfigured();
await loadAgentToken();
const hnsw = await HnswStore.load(s3, keyring, PROCESSED_OUTPUTS_BUCKET, TENANT_ID);
const pipeline = new Pipeline(hnsw, s3, keyring, PROCESSED_OUTPUTS_BUCKET, TENANT_ID);

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
        hnsw,
        s3,
        keyring,
        processedBucket: PROCESSED_OUTPUTS_BUCKET,
      }),
    // ADL #12: synthesized wiki text is ciphertext at rest; the read path decrypts
    // audience-visible blocks here, in-enclave, over the sealed key.
    wikiContentDecryptor: new EnclaveWikiContentDecryptor(keyring),
    // ADL #12/#45: mined draft→edit prose is sealed to the same key, in-enclave only.
    wikiEditSealer: new EnclaveWikiEditSealer(keyring),
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
    keyring,
    processedBucket: PROCESSED_OUTPUTS_BUCKET,
    synthesisQueueUrl: SYNTHESIS_REQUEST_QUEUE_URL,
    processedQueueUrl: PROCESSED_QUEUE_URL,
    previewFetcher: fetchLinkPreview,
  }).start();
}

async function shutdown(): Promise<void> {
  console.log('enclave shutting down — saving hnsw index');
  await hnsw.save(s3, keyring, PROCESSED_OUTPUTS_BUCKET, TENANT_ID);
  if (apiContainer) await apiContainer.close().catch(() => {});
  await haltCache.close().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());

void processLoop(masterKey, pipeline, haltGate);
