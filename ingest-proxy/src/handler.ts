/**
 * Ingest Lambda — the only component that runs outside the enclave.
 *
 * Receives webhooks, encrypts with the tenant's X25519 public key, enqueues
 * to SQS. Holds only a public key — cannot decrypt anything.
 *
 * Scheme: ECIES — ephemeral X25519 + HKDF-SHA256 + AES-256-GCM.
 * Both public keys are bound into HKDF info to prevent key-confusion attacks.
 * Must match decryptPayload() in enclave/src/ingest/receiver.ts exactly.
 */
import { RDSDataClient, ExecuteStatementCommand, type Field } from '@aws-sdk/client-rds-data';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import {
  generateKeyPairSync,
  diffieHellman,
  hkdfSync,
  createCipheriv,
  createPublicKey,
  randomBytes,
} from 'crypto';
import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';

const rds = new RDSDataClient({});
const sqs = new SQSClient({});

const DB_ARN = process.env['DB_ARN']!;
const DB_SECRET_ARN = process.env['DB_SECRET_ARN']!;
const QUEUE_URL = process.env['QUEUE_URL']!;

async function fetchPublicKey(tenantId: string): Promise<Buffer> {
  const result = await rds.send(
    new ExecuteStatementCommand({
      resourceArn: DB_ARN,
      secretArn: DB_SECRET_ARN,
      sql: 'SELECT ingest_public_key FROM tenants WHERE id = :id',
      parameters: [{ name: 'id', value: { stringValue: tenantId } }],
    }),
  );
  const row = result.records?.[0] as Field[] | undefined;
  if (!row) throw new Error(`Unknown tenant: ${tenantId}`);
  return Buffer.from((row[0] as { stringValue: string }).stringValue, 'hex');
}

function deriveAesKey(
  sharedSecret: Buffer,
  ephemeralPubBytes: Buffer,
  recipientPubBytes: Buffer,
): Buffer {
  const info = Buffer.concat([
    Buffer.from('folklore-ingest-v1:'),
    ephemeralPubBytes,
    recipientPubBytes,
  ]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), info, 32));
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const tenantId = event.pathParameters?.['tenant_id'];
  if (!tenantId) return { statusCode: 400 };

  const body = event.body ?? '';
  const recipientPubBytes = await fetchPublicKey(tenantId);

  const recipientPub = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: recipientPubBytes.toString('base64url') },
    format: 'jwk',
  });

  // Ephemeral key — generated per request, discarded after this function returns
  const { privateKey: ephemeralPriv, publicKey: ephemeralPub } = generateKeyPairSync('x25519');
  const ephemeralPubBytes = Buffer.from(
    ephemeralPub.export({ type: 'spki', format: 'der' }).slice(-32),
  );

  const sharedSecret = diffieHellman({ privateKey: ephemeralPriv, publicKey: recipientPub });
  const aesKey = deriveAesKey(sharedSecret, ephemeralPubBytes, recipientPubBytes);

  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted = Buffer.concat([cipher.update(body, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Append auth tag — matches Python AESGCM convention, split in receiver.ts
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  await sqs.send(
    new SendMessageCommand({
      QueueUrl: QUEUE_URL,
      MessageBody: JSON.stringify({
        tenant_id: tenantId,
        ephemeralPublicKey: ephemeralPubBytes.toString('hex'),
        nonce: nonce.toString('hex'),
        ciphertext: ciphertextWithTag.toString('hex'),
      }),
      MessageGroupId: tenantId,
      MessageDeduplicationId: nonce.toString('hex'),
    }),
  );

  return { statusCode: 200 };
};
