// ECIES: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM. Both public keys bound
// in HKDF info — must match decryptPayload() in enclave/src/ingest/receiver.ts.
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import {
  generateKeyPairSync,
  diffieHellman,
  hkdfSync,
  createCipheriv,
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
} from 'crypto';
import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { jiraEncryptedWebhookEnvelopeSchema } from '@folklore/contracts/enclave';
import { fetchDispatcherAuthSecret, computeDispatcherAuthHmac } from '../dispatcher-auth.js';
import type { RoutingMode } from '../routing-allowlist.js';
import { SQS_MAX_MESSAGE_BYTES } from '../encrypted-sqs-message-size.js';
import { edgeLaneGroupId } from '../edge-lane.js';
import { normalizeHeaders } from '../signature-verifier.js';

const ssm = new SSMClient({});
const sqs = new SQSClient({});

const QUEUE_URL = process.env['QUEUE_URL']!;

const CACHE_TTL_MS = 5 * 60 * 1000;
const X25519_PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/i;
const publicKeyCache = new Map<string, { key: Buffer; expiresAt: number }>();

async function fetchPublicKey(tenantId: string): Promise<Buffer> {
  const cached = publicKeyCache.get(tenantId);
  if (cached && Date.now() < cached.expiresAt) return cached.key;

  const result = await ssm.send(
    new GetParameterCommand({
      Name: `/folklore/${tenantId}/ingest-public-key`,
      WithDecryption: true,
    }),
  );
  const hex = result.Parameter?.Value;
  if (!hex || !X25519_PUBLIC_KEY_HEX.test(hex))
    throw new Error(`No ingest public key for tenant: ${tenantId}`);

  const key = Buffer.from(hex, 'hex');
  publicKeyCache.set(tenantId, { key, expiresAt: Date.now() + CACHE_TTL_MS });
  return key;
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

export function extractEventType(
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
    case 'jira':
    case 'confluence': {
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
    case 'zoom': {
      try {
        return (JSON.parse(body) as { event?: string }).event ?? '';
      } catch {
        return '';
      }
    }
    default:
      return '';
  }
}

function providerDeliveryId(
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
): string | null {
  switch (source) {
    case 'github':
      return null;
    case 'slack': {
      try {
        const id = (JSON.parse(body) as { event_id?: unknown }).event_id;
        return typeof id === 'string' ? id : null;
      } catch {
        return null;
      }
    }
    case 'intercom': {
      try {
        const id = (JSON.parse(body) as { id?: unknown }).id;
        return typeof id === 'string' ? id : null;
      } catch {
        return null;
      }
    }
    case 'zoom': {
      // Zoom dedups on the meeting uuid.
      try {
        const uuid = (JSON.parse(body) as { payload?: { object?: { uuid?: unknown } } }).payload
          ?.object?.uuid;
        return typeof uuid === 'string' ? uuid : null;
      } catch {
        return null;
      }
    }
    default:
      return null;
  }
}

// Key dedup on the delivery, not the per-call ECIES ciphertext, so FIFO drops provider retries.
function deduplicationId(
  tenantId: string,
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
): string {
  const delivery = providerDeliveryId(source, headers, body) ?? body;
  const key = [tenantId, source, delivery].join('\n');
  return createHash('sha256').update(key).digest('hex');
}

async function sealAndEnqueue(params: {
  tenantId: string;
  source: string;
  eventType: string;
  payloadBody: string;
  dedupId: string;
  messageType?: 'jira-oauth-envelope';
}): Promise<void> {
  const recipientPubBytes = await fetchPublicKey(params.tenantId);
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
  const aadFields = {
    version: 2,
    tenant_id: params.tenantId,
    source: params.source,
    type: params.messageType ?? null,
    event_type: params.eventType,
    canary_run_id: null,
    request_id: null,
  };
  const aad = Buffer.from(JSON.stringify(aadFields), 'utf8');
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(params.payloadBody, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);
  const messageBody = JSON.stringify({
    encryption_version: 2,
    tenant_id: params.tenantId,
    source: params.source,
    ...(params.messageType ? { type: params.messageType } : {}),
    eventType: params.eventType,
    ephemeralPublicKey: ephemeralPubBytes.toString('hex'),
    nonce: nonce.toString('hex'),
    ciphertext: ciphertextWithTag.toString('hex'),
  });
  if (Buffer.byteLength(messageBody, 'utf8') > SQS_MAX_MESSAGE_BYTES) {
    throw new Error('sealed_webhook_message_too_large');
  }

  await sqs.send(
    new SendMessageCommand({
      QueueUrl: QUEUE_URL,
      MessageBody: messageBody,
      MessageGroupId: edgeLaneGroupId(
        params.tenantId,
        params.source,
        params.payloadBody,
        params.messageType,
      ),
      MessageDeduplicationId: params.dedupId,
    }),
  );
}

interface DispatcherEvent {
  source: string;
  body: string;
  tenantId: string;
  deliveryId: string;
  headers: Record<string, string>;
  eventType: string;
  authHmac: string;
  routingMode?: RoutingMode;
  authorization?: string;
  method?: string;
  rawPath?: string;
  rawQuery?: string;
  webhookIdentifier?: string;
  routeId?: string;
}

// HMAC-guarded dispatcher invoke: only the dispatcher with the shared secret can invoke.
export async function handleDispatcherInvoke(
  event: DispatcherEvent,
): Promise<{ statusCode: number }> {
  const authSecret = await fetchDispatcherAuthSecret();
  if (!authSecret) return { statusCode: 401 };
  if (event.routingMode !== 'payload' && event.routingMode !== 'url') return { statusCode: 401 };

  const expectedHmac = Buffer.from(
    computeDispatcherAuthHmac(event.tenantId, event.source, authSecret, event.routingMode),
    'hex',
  );

  const provided = Buffer.from(event.authHmac, 'hex');
  if (provided.length !== expectedHmac.length || !timingSafeEqual(provided, expectedHmac)) {
    return { statusCode: 401 };
  }

  const oauthFields = [
    event.authorization,
    event.method,
    event.rawPath,
    event.rawQuery,
    event.webhookIdentifier,
    event.routeId,
  ];
  const hasOAuthFields = oauthFields.some((value) => value !== undefined);
  const hasCompleteOAuthFields = oauthFields.every((value) => typeof value === 'string');
  if (hasOAuthFields && (!hasCompleteOAuthFields || event.source !== 'jira')) {
    return { statusCode: 401 };
  }

  const headers = normalizeHeaders(event.headers);
  let payloadBody: string;
  let messageType: 'jira-oauth-envelope' | undefined;
  if (hasCompleteOAuthFields) {
    const parsedEnvelope = jiraEncryptedWebhookEnvelopeSchema.safeParse({
      version: 1,
      rawBody: event.body,
      authorization: event.authorization,
      method: event.method,
      rawPath: event.rawPath,
      rawQuery: event.rawQuery,
      webhookIdentifier: event.webhookIdentifier,
    });
    if (!parsedEnvelope.success) return { statusCode: 401 };
    payloadBody = JSON.stringify(parsedEnvelope.data);
    messageType = 'jira-oauth-envelope';
  } else {
    payloadBody = event.body;
  }

  const dedupId = event.deliveryId
    ? createHash('sha256')
        .update([event.tenantId, event.source, event.deliveryId].join('\n'))
        .digest('hex')
    : deduplicationId(event.tenantId, event.source, headers, payloadBody);

  await sealAndEnqueue({
    tenantId: event.tenantId,
    source: event.source,
    eventType: event.eventType,
    payloadBody,
    dedupId,
    ...(messageType ? { messageType } : {}),
  });

  return { statusCode: 200 };
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const dispatchEvent = event as unknown as DispatcherEvent;
  if (dispatchEvent.source && dispatchEvent.tenantId && dispatchEvent.body) {
    return handleDispatcherInvoke(dispatchEvent);
  }
  return { statusCode: 400 };
};
