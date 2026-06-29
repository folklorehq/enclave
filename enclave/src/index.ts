import { S3Client, GetObjectCommand, PutObjectCommand, NoSuchKey } from '@aws-sdk/client-s3';
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import { generateMasterKey, deriveIngestKeypair } from './sealing/keygen.js';
import { sealMasterKey, unsealMasterKey } from './sealing/seal.js';
import { decryptPayload, type EncryptedPayload } from './ingest/receiver.js';
import { handle } from './pipeline/index.js';

const REGION = process.env['AWS_REGION']!;
const TENANT_ID = process.env['TENANT_ID']!;
const KMS_KEY_ID = process.env['KMS_KEY_ID']!;
const SEALED_BLOB_BUCKET = process.env['SEALED_BLOB_BUCKET']!;
const SEALED_BLOB_KEY = `sealed-keys/${TENANT_ID}/master.blob`;
const QUEUE_URL = process.env['QUEUE_URL']!;

const s3 = new S3Client({ region: REGION });
const sqs = new SQSClient({ region: REGION });

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
  // TODO: register public key with control plane
  console.log('FIRST_BOOT', { tenant: TENANT_ID, publicKey: publicKeyRaw.toString('hex') });

  return masterKey;
}

async function processLoop(masterKey: Buffer): Promise<void> {
  const { privateKey } = deriveIngestKeypair(masterKey);
  console.log('processing loop started', { queue: QUEUE_URL });

  for (;;) {
    const resp = await sqs.send(
      new ReceiveMessageCommand({
        QueueUrl: QUEUE_URL,
        MaxNumberOfMessages: 10,
        WaitTimeSeconds: 20,
      }),
    );

    for (const msg of resp.Messages ?? []) {
      try {
        const payload = JSON.parse(msg.Body!) as EncryptedPayload;
        const plaintext = decryptPayload(payload, privateKey);
        await handle(plaintext, masterKey);
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
