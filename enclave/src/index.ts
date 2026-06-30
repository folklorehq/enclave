import { S3Client, GetObjectCommand, PutObjectCommand, NoSuchKey } from '@aws-sdk/client-s3';
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import { SSMClient, PutParameterCommand } from '@aws-sdk/client-ssm';
import { KMSClient } from '@aws-sdk/client-kms';
import { KmsKeyringNode } from '@aws-crypto/client-node';
import neo4j from 'neo4j-driver';
import { generateMasterKey, deriveIngestKeypair } from './sealing/keygen.js';
import { sealMasterKey, unsealMasterKey } from './sealing/seal.js';
import { decryptPayload, type EncryptedPayload } from './ingest/receiver.js';
import { createDb } from './db/client.js';
import { EnclaveFactPersister } from './db/persist.js';
import { Pipeline } from './pipeline/index.js';

const REGION = process.env['AWS_REGION']!;
const TENANT_ID = process.env['TENANT_ID']!;
const KMS_KEY_ID = process.env['KMS_KEY_ID']!;
const SEALED_BLOB_BUCKET = process.env['SEALED_BLOB_BUCKET']!;
const QUEUE_URL = process.env['QUEUE_URL']!;
const PROCESSED_OUTPUTS_BUCKET = process.env['PROCESSED_OUTPUTS_BUCKET']!;
const PROXY_PORT = process.env['VSOCK_KMS_PROXY_PORT'] ?? '8000';

const SEALED_BLOB_KEY = `sealed-keys/${TENANT_ID}/master.blob`;
const INGEST_KEY_SSM_PATH = `/folklore/${TENANT_ID}/ingest-public-key`;
const IDLE_SSM_PATH = `/folklore/${TENANT_ID}/idle`;
// After 15 consecutive empty long-polls (~5 min) the enclave signals idle.
const IDLE_POLL_THRESHOLD = 15;

// vsock proxy on the parent EC2 routes all AWS SDK calls without internet egress
const proxyEndpoint = `http://localhost:${PROXY_PORT}`;

const s3 = new S3Client({ region: REGION, endpoint: proxyEndpoint });
const sqs = new SQSClient({ region: REGION, endpoint: proxyEndpoint });
const ssm = new SSMClient({ region: REGION, endpoint: proxyEndpoint });

const keyring = new KmsKeyringNode({
  generatorKeyId: KMS_KEY_ID,
  clientProvider: (r?: string) =>
    new KMSClient({ region: r ?? REGION, endpoint: proxyEndpoint }) as never,
});

const pipeline = new Pipeline(
  new EnclaveFactPersister(
    createDb(),
    keyring,
    s3,
    neo4j.driver(process.env['MEMGRAPH_URL'] ?? 'bolt://localhost:7687'),
    PROCESSED_OUTPUTS_BUCKET,
  ),
  TENANT_ID,
);

interface SqsMessage {
  tenant_id: string;
  source: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
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
  const masterKey = generateMasterKey();
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

async function processLoop(masterKey: Buffer): Promise<void> {
  const { privateKey } = deriveIngestKeypair(masterKey);
  console.log('processing loop started', { queue: QUEUE_URL });

  let idlePolls = 0;
  let isIdle = false;

  for (;;) {
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
      try {
        const raw = JSON.parse(msg.Body!) as SqsMessage;
        const encryptedPayload: EncryptedPayload = {
          ephemeralPublicKey: raw.ephemeralPublicKey,
          nonce: raw.nonce,
          ciphertext: raw.ciphertext,
        };
        const plaintext = decryptPayload(encryptedPayload, privateKey);
        await pipeline.handle(plaintext, raw.source);
        await sqs.send(
          new DeleteMessageCommand({ QueueUrl: QUEUE_URL, ReceiptHandle: msg.ReceiptHandle! }),
        );
      } catch (err) {
        console.error('failed to process message', { id: msg.MessageId, err });
        // Leave in queue — visibility timeout retries, DLQ after 3 attempts
      }
    }
  }
}

processLoop(await boot());
