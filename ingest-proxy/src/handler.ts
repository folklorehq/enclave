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
import { checkRateLimit } from './rate-limiter.js';

const ssm = new SSMClient({});
const sqs = new SQSClient({});

const QUEUE_URL = process.env['QUEUE_URL']!;

const SIGNABLE_SOURCES = new Set([
  'github',
  'slack',
  'linear',
  'jira',
  'intercom',
  'notion',
  'meeting',
]);

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

type SecretLookup =
  | { status: 'found'; secret: string }
  | { status: 'absent' }
  | { status: 'error' };

async function fetchHmacSecret(tenantId: string, source: string): Promise<SecretLookup> {
  const cacheKey = `${tenantId}/${source}`;
  const cached = hmacSecretCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return resolveSecret(cached.secret);

  let secret: string | null;
  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: `/folklore/${tenantId}/webhook-secrets/${source}`,
        WithDecryption: true,
      }),
    );
    secret = result.Parameter?.Value ?? null;
  } catch (err) {
    if (!isParameterNotFound(err)) return { status: 'error' };
    secret = null;
  }

  hmacSecretCache.set(cacheKey, { secret, expiresAt: Date.now() + CACHE_TTL_MS });
  return resolveSecret(secret);
}

function resolveSecret(secret: string | null): SecretLookup {
  return secret === null ? { status: 'absent' } : { status: 'found', secret };
}

function isParameterNotFound(err: unknown): boolean {
  return err instanceof Error && err.name === 'ParameterNotFound';
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
      // Linear sends `Linear-Signature`, which arrives lowercased through API Gateway.
      const sig = headers['linear-signature'];
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

    case 'jira': {
      // Jira has no native webhook signing; a customer Automation rule HMAC-SHA256s the body.
      const sig = headers['x-atlassian-webhook-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'notion': {
      // Notion signs with the subscription verification_token, not an app secret.
      const sig = headers['x-notion-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'meeting': {
      // Fireflies-style HMAC over the raw body (no basestring, unlike Slack).
      const sig = headers['x-meeting-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    default:
      // Fail closed: a source with no known signature scheme is never admitted.
      return false;
  }
}

export function deriveAesKey(
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
    case 'jira': {
      try {
        return (JSON.parse(body) as { webhookEvent?: string }).webhookEvent ?? '';
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
  if (!SIGNABLE_SOURCES.has(source)) return { statusCode: 400 };

  const body = event.body ?? '';

  // Fail closed: a supported source is admitted only when a provisioned secret
  // verifies the signature. An absent secret or a bad signature is a 401
  // (forged-event injection guard); a transient SSM error is a 503 so the
  // provider retries rather than the webhook being dropped (durability).
  const lookup = await fetchHmacSecret(tenantId, source);
  if (lookup.status === 'error') return { statusCode: 503 };
  if (lookup.status === 'absent') return { statusCode: 401 };
  if (!verifySignature(source, event.headers, body, lookup.secret)) {
    return { statusCode: 401 };
  }

  if (!(await checkRateLimit(tenantId, source))) {
    return { statusCode: 429 };
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
