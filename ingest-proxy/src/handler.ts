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
  'confluence',
  'intercom',
  'notion',
  'meeting',
  'google_drive',
  'microsoft365',
  'zoom',
  'zoom_bot',
]);

const GOOGLE_DRIVE_SOURCE = 'google_drive';
const MICROSOFT365_SOURCE = 'microsoft365';
// Drive push channels have no body signature; validity is the channel token we set at watch() time,
// and the initial `sync` state is a handshake carrying no change (Google Drive push notifications).
const DRIVE_SYNC_STATE = 'sync';

// Atlassian Connect authenticates webhooks with a JWT (Authorization: JWT <token>), HS256-signed
// with the app-install shared secret — not an HMAC body signature. `alg: none` is rejected.
const CONNECT_JWT_PREFIX = 'jwt ';
const JWT_CLOCK_SKEW_S = 60;

const CACHE_TTL_MS = 5 * 60 * 1000;
const MS_PER_S = 1000;
const SLACK_REPLAY_TOLERANCE_S = 300;
const SVIX_REPLAY_TOLERANCE_S = 300;
const SVIX_SECRET_PREFIX = 'whsec_';
const ZOOM_REPLAY_TOLERANCE_S = 300;
// Recall.ai signs every tenant's bot webhook with ONE workspace-level verification secret (Svix
// scheme), not a per-tenant secret (design §4): inbound isolation rests on the unguessable per-tenant
// ingest URL alone. Recall bots post to the `zoom` source path (design §8 — no `zoom_bot` SourceKind).
const RECALL_WEBHOOK_SECRET_PATH = '/folklore/recall-api/webhook-verification-secret';
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

async function fetchSecretAt(name: string, cacheKey: string): Promise<SecretLookup> {
  const cached = hmacSecretCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return resolveSecret(cached.secret);

  let secret: string | null;
  try {
    const result = await ssm.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
    secret = result.Parameter?.Value ?? null;
  } catch (err) {
    if (!isParameterNotFound(err)) return { status: 'error' };
    secret = null;
  }

  hmacSecretCache.set(cacheKey, { secret, expiresAt: Date.now() + CACHE_TTL_MS });
  return resolveSecret(secret);
}

function fetchHmacSecret(tenantId: string, source: string): Promise<SecretLookup> {
  return fetchSecretAt(`/folklore/${tenantId}/webhook-secrets/${source}`, `${tenantId}/${source}`);
}

// A Recall bot transcript and a native-Zoom event both land on the `zoom` source path but sign
// differently: Recall uses Svix headers (global secret), native Zoom uses `x-zm-signature` (per-tenant
// Zoom Secret Token). Presence of a Svix signature header disambiguates the Recall producer.
function isRecallInbound(source: string, headers: Record<string, string | undefined>): boolean {
  if (source !== 'zoom') return false;
  return Boolean(headers['webhook-signature'] ?? headers['svix-signature']);
}

function resolveSecret(secret: string | null): SecretLookup {
  return secret === null ? { status: 'absent' } : { status: 'found', secret };
}

// Signature verification must not depend on API Gateway lowercasing header keys: a
// relay, ALB, function URL, or direct invoke can preserve the provider's original
// casing (Linear sends `Linear-Signature`). Lowercase once, look up lowercase.
function normalizeHeaders(
  headers: Record<string, string | undefined> | undefined,
): Record<string, string | undefined> {
  const normalized: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

function isParameterNotFound(err: unknown): boolean {
  return err instanceof Error && err.name === 'ParameterNotFound';
}

// Reject a signed request whose timestamp is missing, non-numeric (NaN → fail closed), or
// outside the replay window — the basestring includes the timestamp, so this bounds replay.
function withinReplayWindow(ts: string | undefined, toleranceS: number): boolean {
  const tsNum = Number(ts);
  return Number.isFinite(tsNum) && Math.abs(Date.now() / MS_PER_S - tsNum) <= toleranceS;
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
      if (!sig?.startsWith('v0=')) return false;
      if (!withinReplayWindow(ts, SLACK_REPLAY_TOLERANCE_S)) return false;
      const basestring = `v0:${ts}:${body}`;
      const expected = Buffer.from(sig.slice(3), 'hex');
      const computed = createHmac('sha256', secret).update(basestring, 'utf8').digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'linear': {
      // Linear sends `Linear-Signature`; normalizeHeaders lowercases the key.
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
      // Native Jira Cloud WebSub signing (secret set at webhook registration): X-Hub-Signature,
      // sha256 over the raw body — same header as Intercom (sha1), disambiguated by source path.
      const sig = headers['x-hub-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'confluence': {
      // The provisioned secret is the Atlassian Connect app-install shared secret.
      return verifyConnectJwt(headers['authorization'], secret);
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
      // Transcript-upload HMAC over the raw body (no basestring, unlike Slack).
      const sig = headers['x-meeting-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'zoom_bot':
      // Recall.ai signs via Svix: base64 HMAC-SHA256 over `${id}.${timestamp}.${body}`.
      return verifySvixSignature(headers, body, secret);

    case GOOGLE_DRIVE_SOURCE: {
      // Drive push has no HMAC — validity is a constant-time match on the watch()-time channel token.
      const token = headers['x-goog-channel-token'];
      if (!token) return false;
      const expected = Buffer.from(secret, 'utf8');
      const provided = Buffer.from(token, 'utf8');
      return expected.length === provided.length && timingSafeEqual(expected, provided);
    }

    case MICROSOFT365_SOURCE: {
      // Graph change notifications carry no body HMAC — validity is the clientState we set at
      // subscription time, matched constant-time against EVERY notification. Fail closed on any miss.
      let parsed: { value?: Array<{ clientState?: unknown }> };
      try {
        parsed = JSON.parse(body);
      } catch {
        return false;
      }
      const notifications = parsed.value;
      if (!Array.isArray(notifications) || notifications.length === 0) return false;
      const expected = Buffer.from(secret, 'utf8');
      return notifications.every((n) => {
        if (typeof n.clientState !== 'string') return false;
        const provided = Buffer.from(n.clientState, 'utf8');
        return expected.length === provided.length && timingSafeEqual(expected, provided);
      });
    }

    case 'zoom': {
      // Zoom Secret Token: v0= + HMAC-SHA256 over `v0:{timestamp}:{body}` (like Slack's basestring).
      const sig = headers['x-zm-signature'];
      const ts = headers['x-zm-request-timestamp'];
      if (!sig?.startsWith('v0=')) return false;
      if (!withinReplayWindow(ts, ZOOM_REPLAY_TOLERANCE_S)) return false;
      const basestring = `v0:${ts}:${body}`;
      const expected = Buffer.from(sig.slice(3), 'hex');
      const computed = createHmac('sha256', secret).update(basestring, 'utf8').digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    default:
      // Fail closed: a source with no known signature scheme is never admitted.
      return false;
  }
}

function svixKey(secret: string): Buffer {
  const raw = secret.startsWith(SVIX_SECRET_PREFIX)
    ? secret.slice(SVIX_SECRET_PREFIX.length)
    : secret;
  return Buffer.from(raw, 'base64');
}

function verifySvixSignature(
  headers: Record<string, string | undefined>,
  body: string,
  secret: string,
): boolean {
  const id = headers['webhook-id'] ?? headers['svix-id'];
  const ts = headers['webhook-timestamp'] ?? headers['svix-timestamp'];
  const sigHeader = headers['webhook-signature'] ?? headers['svix-signature'];
  if (!id || !ts || !sigHeader) return false;
  if (!withinReplayWindow(ts, SVIX_REPLAY_TOLERANCE_S)) return false;

  const expected = createHmac('sha256', svixKey(secret))
    .update(`${id}.${ts}.${body}`, 'utf8')
    .digest();

  for (const token of sigHeader.split(' ')) {
    const comma = token.indexOf(',');
    const provided = Buffer.from(comma === -1 ? token : token.slice(comma + 1), 'base64');
    if (provided.length === expected.length && timingSafeEqual(provided, expected)) return true;
  }
  return false;
}

const ZOOM_URL_VALIDATION_EVENT = 'endpoint.url_validation';

interface ChallengeResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

function zoomUrlValidation(source: string, body: string, secret: string): ChallengeResponse | null {
  if (source !== 'zoom') return null;
  let parsed: { event?: string; payload?: { plainToken?: unknown } };
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (parsed.event !== ZOOM_URL_VALIDATION_EVENT) return null;
  const plainToken = parsed.payload?.plainToken;
  if (typeof plainToken !== 'string') return null;
  const encryptedToken = createHmac('sha256', secret).update(plainToken).digest('hex');
  return {
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ plainToken, encryptedToken }),
  };
}

// Graph confirms a subscription by GET/POSTing ?validationToken=<opaque> and requires the raw token
// echoed back as text/plain within 10s. It carries no clientState, so it precedes signature checks.
function microsoft365ValidationEcho(
  source: string,
  query: Record<string, string | undefined> | undefined,
): ChallengeResponse | null {
  if (source !== MICROSOFT365_SOURCE) return null;
  const token = query?.['validationToken'];
  if (typeof token !== 'string' || token.length === 0) return null;
  return { statusCode: 200, headers: { 'content-type': 'text/plain' }, body: token };
}

// Verify signature + expiry only; qsh (query-string-hash) is not enforced — the shared-secret
// HS256 signature is the forgery gate, and reconstructing the canonical request behind API
// Gateway is brittle. iss/clientKey binding is enforced upstream by the per-tenant secret path.
function verifyConnectJwt(authHeader: string | undefined, secret: string): boolean {
  if (!authHeader || !authHeader.toLowerCase().startsWith(CONNECT_JWT_PREFIX)) return false;
  const [headerB64, payloadB64, signatureB64] = authHeader
    .slice(CONNECT_JWT_PREFIX.length)
    .trim()
    .split('.');
  if (!headerB64 || !payloadB64 || !signatureB64) return false;

  const header = decodeJwtSegment(headerB64);
  if (header?.['alg'] !== 'HS256') return false;

  const expected = createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest();
  const provided = Buffer.from(signatureB64, 'base64url');
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return false;

  const payload = decodeJwtSegment(payloadB64);
  if (!payload) return false;
  const exp = payload['exp'];
  const now = Math.floor(Date.now() / MS_PER_S);
  if (typeof exp !== 'number' || now > exp + JWT_CLOCK_SKEW_S) return false;
  return true;
}

function decodeJwtSegment(segment: string): Record<string, unknown> | null {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
  } catch {
    return null;
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

// Notion's subscription handshake POSTs a bare `{ verification_token }` with no signature — the
// token IS the future signing secret, so nothing can sign this first contact. Distinguish it from a
// signed event so we can 2xx it instead of failing the signature check and rejecting the endpoint.
function isNotionVerificationHandshake(
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
): boolean {
  if (source !== 'notion' || headers['x-notion-signature']) return false;
  try {
    const parsed = JSON.parse(body) as { verification_token?: unknown; type?: unknown };
    return typeof parsed.verification_token === 'string' && parsed.type === undefined;
  } catch {
    return false;
  }
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
    case GOOGLE_DRIVE_SOURCE:
      return headers['x-goog-resource-state'] ?? '';
    case MICROSOFT365_SOURCE: {
      try {
        return (
          (JSON.parse(body) as { value?: Array<{ changeType?: string }> }).value?.[0]?.changeType ??
          ''
        );
      } catch {
        return '';
      }
    }
    case 'zoom_bot':
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

// A Drive ping ships its change signal in headers with an empty body; rebuild a content-free
// payload (opaque resource/channel ids only) so the enclave normalizer can record the signal.
function driveChangePingBody(headers: Record<string, string | undefined>): string {
  return JSON.stringify({
    resourceState: headers['x-goog-resource-state'] ?? '',
    resourceId: headers['x-goog-resource-id'],
    channelId: headers['x-goog-channel-id'],
    messageNumber: headers['x-goog-message-number'],
    resourceUri: headers['x-goog-resource-uri'],
  });
}

// A Graph notification body carries the clientState (our webhook secret) — strip it and re-emit only
// content-free routing metadata (subscription/resource ids + changeType) so no secret reaches SQS/enclave.
function m365ChangePingBody(body: string): string {
  let parsed: {
    value?: Array<{ subscriptionId?: unknown; resource?: unknown; changeType?: unknown }>;
  };
  try {
    parsed = JSON.parse(body);
  } catch {
    return JSON.stringify({ notifications: [] });
  }
  const notifications = (parsed.value ?? []).map((n) => ({
    subscriptionId: typeof n.subscriptionId === 'string' ? n.subscriptionId : undefined,
    resource: typeof n.resource === 'string' ? n.resource : undefined,
    changeType: typeof n.changeType === 'string' ? n.changeType : undefined,
  }));
  return JSON.stringify({ notifications });
}

function providerDeliveryId(
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
): string | null {
  switch (source) {
    case 'github':
      return headers['x-github-delivery'] ?? null;
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
    case 'zoom_bot':
      // Svix message id uniquely identifies a delivery, so FIFO drops Recall's retries.
      return headers['webhook-id'] ?? headers['svix-id'] ?? null;
    case GOOGLE_DRIVE_SOURCE: {
      // Each Drive push is a unique (channel, message-number) pair — the dedup key across retries.
      const channelId = headers['x-goog-channel-id'];
      const messageNumber = headers['x-goog-message-number'];
      return channelId && messageNumber ? `${channelId}:${messageNumber}` : null;
    }
    case MICROSOFT365_SOURCE: {
      // (subscription, resource) identifies the changed drive item — the dedup key across Graph retries.
      try {
        const first = (
          JSON.parse(body) as {
            value?: Array<{ subscriptionId?: unknown; resource?: unknown }>;
          }
        ).value?.[0];
        const sub = typeof first?.subscriptionId === 'string' ? first.subscriptionId : null;
        const resource = typeof first?.resource === 'string' ? first.resource : null;
        return sub && resource ? `${sub}:${resource}` : null;
      } catch {
        return null;
      }
    }
    case 'zoom': {
      // A Recall bot on the `zoom` path dedups on its Svix message id; native Zoom on the meeting uuid.
      const svixId = headers['webhook-id'] ?? headers['svix-id'];
      if (svixId) return svixId;
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

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const tenantId = event.pathParameters?.['tenant_id'];
  const source = event.pathParameters?.['source'];
  if (!tenantId || !source) return { statusCode: 400 };
  if (!SIGNABLE_SOURCES.has(source)) return { statusCode: 400 };

  const body = event.body ?? '';
  const headers = normalizeHeaders(event.headers);

  // ACK Notion's unsigned subscription handshake (it carries only the verification_token, which the
  // admin registers as the webhook secret) without treating it as an event or forwarding it to SQS.
  if (isNotionVerificationHandshake(source, event.headers, body)) return { statusCode: 200 };

  // Graph subscription validation: echo the opaque validationToken as text/plain (no clientState
  // yet, so it precedes the signature gate — the token echo carries no secret and admits nothing).
  const graphValidation = microsoft365ValidationEcho(source, event.queryStringParameters);
  if (graphValidation) return graphValidation;

  // Fail closed: a supported source is admitted only when a provisioned secret
  // verifies the signature. An absent secret or a bad signature is a 401
  // (forged-event injection guard); a transient SSM error is a 503 so the
  // provider retries rather than the webhook being dropped (durability).
  // Recall inbound verifies against the single global workspace secret (Svix); every other producer
  // (incl. native Zoom on the same `zoom` path) verifies against its per-tenant secret. Fail closed.
  const recallInbound = isRecallInbound(source, headers);
  const lookup = recallInbound
    ? await fetchSecretAt(RECALL_WEBHOOK_SECRET_PATH, RECALL_WEBHOOK_SECRET_PATH)
    : await fetchHmacSecret(tenantId, source);
  if (lookup.status === 'error') return { statusCode: 503 };
  if (lookup.status === 'absent') return { statusCode: 401 };
  // Signature FIRST, even for Zoom's url_validation (which Zoom also signs): answering the CRC
  // echo HMAC(secret, plainToken) before verifying turns it into a forgery oracle for the
  // message signature HMAC(secret, `v0:{ts}:{body}`) over the same secret. Gating on a valid
  // signature means only a secret-holder (genuine Zoom) can reach the echo.
  const signatureValid = recallInbound
    ? verifySvixSignature(headers, body, lookup.secret)
    : verifySignature(source, headers, body, lookup.secret);
  if (!signatureValid) {
    return { statusCode: 401 };
  }

  // The channel-creation handshake carries no change — ack it without enqueuing anything.
  if (source === GOOGLE_DRIVE_SOURCE && headers['x-goog-resource-state'] === DRIVE_SYNC_STATE) {
    return { statusCode: 200 };
  }

  // The CRC echo is native-Zoom-only (its own Secret Token); a Recall payload never carries it.
  if (!recallInbound) {
    const challenge = zoomUrlValidation(source, body, lookup.secret);
    if (challenge) return challenge;
  }

  if (!(await checkRateLimit(tenantId, source))) {
    return { statusCode: 429 };
  }

  // Drive pings have an empty body (signal in headers); Graph notifications carry the clientState
  // secret — both are re-emitted content-free so no secret or unneeded payload reaches SQS/enclave.
  const payloadBody =
    source === GOOGLE_DRIVE_SOURCE
      ? driveChangePingBody(headers)
      : source === MICROSOFT365_SOURCE
        ? m365ChangePingBody(body)
        : body;

  const eventType = extractEventType(source, headers, body);
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
  const encrypted = Buffer.concat([cipher.update(payloadBody, 'utf8'), cipher.final()]);
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
      MessageDeduplicationId: deduplicationId(tenantId, source, headers, payloadBody),
    }),
  );

  return { statusCode: 200 };
};
