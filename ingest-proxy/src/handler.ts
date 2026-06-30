// ECIES: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM. Both public keys bound
// in HKDF info — must match decryptPayload() in enclave/src/ingest/receiver.ts.
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
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

const ssm = new SSMClient({});
const sqs = new SQSClient({});

const QUEUE_URL = process.env['QUEUE_URL']!;

const CACHE_TTL_MS = 5 * 60 * 1000;
const publicKeyCache = new Map<string, { key: Buffer; expiresAt: number }>();

async function fetchPublicKey(tenantId: string): Promise<Buffer> {
  const cached = publicKeyCache.get(tenantId);
  if (cached && Date.now() < cached.expiresAt) return cached.key;

  const result = await ssm.send(
    new GetParameterCommand({ Name: `/folklore/${tenantId}/ingest-public-key` }),
  );
  const hex = result.Parameter?.Value;
  if (!hex) throw new Error(`No ingest public key for tenant: ${tenantId}`);

  const key = Buffer.from(hex, 'hex');
  publicKeyCache.set(tenantId, { key, expiresAt: Date.now() + CACHE_TTL_MS });
  return key;
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

function extractEventType(
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
): string {
  switch (source) {
    case 'github':
      return headers['x-github-event'] ?? '';
    case 'slack': {
      try {
        return (JSON.parse(body) as { type?: string }).type ?? '';
      } catch {
        return '';
      }
    }
    case 'linear': {
      try {
        return (JSON.parse(body) as { type?: string }).type ?? '';
      } catch {
        return '';
      }
    }
    case 'notion': {
      try {
        return (JSON.parse(body) as { type?: string }).type ?? '';
      } catch {
        return '';
      }
    }
    case 'intercom':
      return headers['x-intercom-topic'] ?? '';
    case 'meeting':
      return headers['x-meeting-event'] ?? '';
    default:
      return '';
  }
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const tenantId = event.pathParameters?.['tenant_id'];
  const source = event.pathParameters?.['source'];
  if (!tenantId || !source) return { statusCode: 400 };

  const body = event.body ?? '';
  const eventType = extractEventType(source, event.headers, body);
  const recipientPubBytes = await fetchPublicKey(tenantId);

  const recipientPub = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: recipientPubBytes.toString('base64url') },
    format: 'jwk',
  });

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
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  await sqs.send(
    new SendMessageCommand({
      QueueUrl: QUEUE_URL,
      MessageBody: JSON.stringify({
        tenant_id: tenantId,
        source,
        eventType,
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
