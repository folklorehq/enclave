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
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'crypto';
import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';

const ssm = new SSMClient({});
const sqs = new SQSClient({});

const QUEUE_URL = process.env['QUEUE_URL']!;

const CACHE_TTL_MS = 5 * 60 * 1000;
const publicKeyCache = new Map<string, { key: Buffer; expiresAt: number }>();
const hmacSecretCache = new Map<string, { secret: string | null; expiresAt: number }>();

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

async function fetchHmacSecret(tenantId: string, source: string): Promise<string | null> {
  const cacheKey = `${tenantId}/${source}`;
  const cached = hmacSecretCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return cached.secret;

  let secret: string | null = null;
  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: `/folklore/${tenantId}/webhook-secrets/${source}`,
        WithDecryption: true,
      }),
    );
    secret = result.Parameter?.Value ?? null;
  } catch {
    // ParameterNotFound or access denied — no secret configured yet
  }

  hmacSecretCache.set(cacheKey, { secret, expiresAt: Date.now() + CACHE_TTL_MS });
  return secret;
}

function verifySignature(
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
  secret: string,
): boolean {
  const bodyBuf = Buffer.from(body, 'utf8');

  switch (source) {
    case 'github': {
      const sig = headers['x-hub-signature-256'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'slack': {
      const sig = headers['x-slack-signature'];
      const ts = headers['x-slack-request-timestamp'];
      if (!sig?.startsWith('v0=') || !ts) return false;
      // Reject replays older than 5 minutes
      if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
      const basestring = `v0:${ts}:${body}`;
      const expected = Buffer.from(sig.slice(3), 'hex');
      const computed = createHmac('sha256', secret).update(basestring, 'utf8').digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'linear': {
      const sig = headers['x-linear-signature'];
      if (!sig) return false;
      const expected = Buffer.from(sig, 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'intercom': {
      // Intercom sends X-Hub-Signature: sha1=<hex>
      const sig = headers['x-hub-signature'];
      if (!sig?.startsWith('sha1=')) return false;
      const expected = Buffer.from(sig.slice(5), 'hex');
      const computed = createHmac('sha1', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    default:
      // No known signature scheme for this source — allow through
      return true;
  }
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

  // Verify HMAC signature if a secret is configured for this tenant+source.
  // Fail-open when no secret exists (connector not yet onboarded);
  // reject with 401 when a secret is present but the signature is wrong.
  const hmacSecret = await fetchHmacSecret(tenantId, source);
  if (hmacSecret !== null) {
    if (!verifySignature(source, event.headers, body, hmacSecret)) {
      return { statusCode: 401 };
    }
  }

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
