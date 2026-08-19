import { createHmac } from 'crypto';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { resolveTenant, EXTRACTORS } from './tenant-resolver.js';
import { verifySignature, normalizeHeaders } from './signature-verifier.js';
import { extractEventType } from './lambdas/handler.js';
import { jiraEncryptedWebhookEnvelopeSchema } from '@folklore/contracts/enclave';
import { fitsEncryptedSqsMessage } from './encrypted-sqs-message-size.js';
import { checkRateLimit } from './rate-limiter.js';
import { fetchDispatcherAuthSecret, computeDispatcherAuthHmac } from './dispatcher-auth.js';
import {
  captureNotionVerificationToken,
  getNotionVerificationCaptureConfig,
  isNotionVerificationChallenge,
} from './notion-verification-capture.js';
import {
  findRoutingAllowlistEntry,
  normalizeRoutingAllowlist,
  oauthRouteHmacMessage,
  timingSafeStringEqual,
  verifyRoutingHmac,
  verifyOAuthRouteHmac,
  type RoutingMode,
} from './routing-allowlist.js';

const ssm = new SSMClient({});
const ddb = new DynamoDBClient({});
const lambda = new LambdaClient({});

const CACHE_TTL_MS = 5 * 60 * 1000;
// Pre-auth abuse guard matches the API Gateway cap; the per-tenant replay quota is enforced after JWT verification in the enclave.
const JIRA_PREAUTH_ABUSE_WINDOW_MS = 60 * 1000;
const JIRA_PREAUTH_ABUSE_LIMIT_PER_MINUTE = 6_000;
const MAX_JIRA_ADMISSION_BUCKETS = 4096;
const secretCache = new Map<string, { secret: string; expiresAt: number }>();
const allowlistCache = new Map<
  string,
  { entries: ReturnType<typeof normalizeRoutingAllowlist>; expiresAt: number }
>();
const allowlistRefreshes = new Map<string, Promise<RoutingAllowlistLookup>>();
const jiraAdmissionBuckets = new Map<string, { windowStartedAt: number; count: number }>();

const SHARED_SECRET_SSM_PREFIX = '/folklore/shared-webhook-secrets';
const PER_TENANT_SECRET_SSM_PREFIX = '/folklore';
const ROUTING_TABLE = process.env['WEBHOOK_ROUTING_TABLE'] ?? '';
const ZOOM_SOURCE = 'zoom';
const ZOOM_URL_VALIDATION_EVENT = 'endpoint.url_validation';
const MICROSOFT365_SOURCE = 'microsoft365';
const INTERCOM_SOURCE = 'intercom';
const INTERCOM_LIVENESS_ROUTE = 'HEAD /ingest/intercom';
const JIRA_SOURCE = 'jira';
const MAX_JIRA_RAW_BODY_BYTES = 2_000_000;
const ROUTING_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_JIRA_ADMISSION_TOKEN_BYTES = 16 * 1024;
const JIRA_ADMISSION_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_RATE_LIMIT_ID_BYTES = 128;

// Returns null (never invokes downstream) when the shared auth secret isn't provisioned,
// rather than sending an invoke the receiving ingest Lambda is guaranteed to reject.
async function buildInvokePayload(
  destTenantId: string,
  destSource: string,
  destBody: string,
  destHeaders: Record<string, string | undefined>,
  destFunctionName: string,
  mode: RoutingMode,
  oauthContext?: OAuthDispatchContext,
): Promise<{
  FunctionName: string;
  InvocationType: 'RequestResponse';
  Payload: Buffer;
} | null> {
  const secret = await fetchDispatcherAuthSecret();
  if (!secret) return null;

  return {
    FunctionName: destFunctionName,
    InvocationType: 'RequestResponse' as const,
    Payload: Buffer.from(
      JSON.stringify({
        source: destSource,
        body: destBody,
        tenantId: destTenantId,
        deliveryId:
          destHeaders['x-github-delivery'] ??
          destHeaders['webhook-id'] ??
          destHeaders['x-atlassian-webhook-identifier'] ??
          '',
        authHmac: computeDispatcherAuthHmac(destTenantId, destSource, secret, mode),
        routingMode: mode,
        eventType: extractEventType(destSource, destHeaders, destBody),
        headers: destHeaders,
        ...(oauthContext ?? {}),
      }),
    ),
  };
}

function downstreamInvokeSucceeded(result: {
  FunctionError?: string;
  Payload?: Uint8Array;
}): boolean {
  if (result.FunctionError || !result.Payload) return false;
  try {
    const value: unknown = JSON.parse(Buffer.from(result.Payload).toString('utf8'));
    if (!value || typeof value !== 'object') return false;
    const statusCode = (value as Record<string, unknown>)['statusCode'];
    return typeof statusCode === 'number' && statusCode >= 200 && statusCode < 300;
  } catch {
    return false;
  }
}

interface OAuthDispatchContext {
  authorization: string;
  method: string;
  rawPath: string;
  rawQuery: string;
  webhookIdentifier: string;
  routeId: string;
}

interface OAuthRouteCapability {
  routeId: string;
  orgId: string;
  source: string;
  attestationGeneration: string;
}

type OAuthRouteCapabilityLookup =
  | { status: 'found'; capability: OAuthRouteCapability }
  | { status: 'missing' }
  | { status: 'unavailable' };

type RoutingAllowlistLookup =
  | { status: 'found'; entries: ReturnType<typeof normalizeRoutingAllowlist> }
  | { status: 'missing' }
  | { status: 'unavailable' };

async function fetchRoutingAllowlist(
  orgId: string,
  forceRefresh = false,
): Promise<RoutingAllowlistLookup> {
  const cached = allowlistCache.get(orgId);
  if (!forceRefresh && cached && Date.now() < cached.expiresAt) {
    return { status: 'found', entries: cached.entries };
  }
  if (forceRefresh) {
    const activeRefresh = allowlistRefreshes.get(orgId);
    if (activeRefresh) return activeRefresh;
    const refresh = readRoutingAllowlist(orgId);
    allowlistRefreshes.set(orgId, refresh);
    try {
      return await refresh;
    } finally {
      if (allowlistRefreshes.get(orgId) === refresh) allowlistRefreshes.delete(orgId);
    }
  }
  return readRoutingAllowlist(orgId);
}

async function readRoutingAllowlist(orgId: string): Promise<RoutingAllowlistLookup> {
  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: `/folklore/${orgId}/webhook-routing-allowlist`,
        WithDecryption: false,
      }),
    );
    const value = result.Parameter?.Value;
    if (value === undefined) return { status: 'unavailable' };
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return { status: 'unavailable' };
    const entries = normalizeRoutingAllowlist(parsed);
    allowlistCache.set(orgId, { entries, expiresAt: Date.now() + CACHE_TTL_MS });
    return { status: 'found', entries };
  } catch (error) {
    if (error instanceof Error && error.name === 'ParameterNotFound') {
      return { status: 'missing' };
    }
    return { status: 'unavailable' };
  }
}

type RoutingDecision = 'allowed' | 'denied' | 'unavailable';

async function isRoutingAllowed(
  orgId: string,
  source: string,
  mode: RoutingMode,
): Promise<RoutingDecision> {
  const lookup = await fetchRoutingAllowlist(orgId);
  if (lookup.status === 'unavailable') return 'unavailable';
  if (lookup.status === 'missing') return 'denied';
  const entry = findRoutingAllowlistEntry(lookup.entries, orgId, source, mode);
  if (!entry?.hmac) return 'denied';
  const secret = await fetchPerTenantSecret(orgId, source);
  if (!secret) return 'unavailable';
  const expected = createHmac('sha256', secret).update(`${orgId}:${source}:${mode}`).digest('hex');
  return verifyRoutingHmac(expected, entry.hmac, entry.previousHmac) ? 'allowed' : 'denied';
}

async function fetchOAuthRouteCapability(routeId: string): Promise<OAuthRouteCapabilityLookup> {
  if (!ROUTING_TABLE) return { status: 'missing' };

  try {
    const result = await ddb.send(
      new GetItemCommand({
        TableName: ROUTING_TABLE,
        Key: { routingKey: { S: `oauth#${routeId}` } },
        ProjectionExpression: 'routeId, orgId, source, attestationGeneration',
        ConsistentRead: true,
      }),
    );
    const item = result.Item;
    const capability = {
      routeId: item?.['routeId']?.S,
      orgId: item?.['orgId']?.S,
      source: item?.['source']?.S,
      attestationGeneration: item?.['attestationGeneration']?.S,
    };
    if (
      !capability.routeId ||
      !capability.orgId ||
      !capability.source ||
      !capability.attestationGeneration
    ) {
      return { status: 'missing' };
    }
    return { status: 'found', capability: capability as OAuthRouteCapability };
  } catch {
    return { status: 'unavailable' };
  }
}

async function isOAuthRoutingAllowed(
  orgId: string,
  source: string,
  routeId: string,
): Promise<RoutingDecision> {
  let lookup = await fetchRoutingAllowlist(orgId);
  if (lookup.status === 'unavailable') return 'unavailable';
  if (lookup.status === 'missing') return 'denied';
  let entry = findRoutingAllowlistEntry(lookup.entries, orgId, source, 'url');
  if (!entry?.hmac) return 'denied';

  const secret = await fetchPerTenantSecret(orgId, source);
  if (!secret) return 'unavailable';
  const expectedRoutingHmac = createHmac('sha256', secret)
    .update(`${orgId}:${source}:url`)
    .digest('hex');
  if (!verifyRoutingHmac(expectedRoutingHmac, entry.hmac, entry.previousHmac)) return 'denied';

  const cachedRouteMatches =
    entry.routeId !== undefined && timingSafeStringEqual(routeId, entry.routeId);
  if (!cachedRouteMatches) {
    allowlistCache.delete(orgId);
    lookup = await fetchRoutingAllowlist(orgId, true);
    if (lookup.status === 'unavailable') return 'unavailable';
    if (lookup.status === 'missing') return 'denied';
    entry = findRoutingAllowlistEntry(lookup.entries, orgId, source, 'url');
    if (!entry?.hmac) return 'denied';
  }

  if (!entry.routeId || !timingSafeStringEqual(routeId, entry.routeId)) return 'denied';

  const refreshedRoutingHmac = createHmac('sha256', secret)
    .update(`${orgId}:${source}:url`)
    .digest('hex');
  if (!verifyRoutingHmac(refreshedRoutingHmac, entry.hmac, entry.previousHmac)) return 'denied';
  if (!entry.routeHmac || !entry.attestationGeneration) return 'denied';

  const expectedRouteHmac = createHmac('sha256', secret)
    .update(oauthRouteHmacMessage(orgId, source, routeId))
    .digest('hex');
  if (!verifyOAuthRouteHmac(entry.routeHmac, expectedRouteHmac)) return 'denied';

  const capabilityLookup = await fetchOAuthRouteCapability(routeId);
  if (capabilityLookup.status === 'unavailable') return 'unavailable';
  if (capabilityLookup.status === 'missing') return 'denied';
  const capabilityMatches =
    timingSafeStringEqual(capabilityLookup.capability.routeId, routeId) &&
    capabilityLookup.capability.orgId === orgId &&
    capabilityLookup.capability.source === source;
  if (!capabilityMatches) return 'denied';
  return capabilityLookup.capability.attestationGeneration === entry.attestationGeneration
    ? 'allowed'
    : 'denied';
}

function consumeJiraAdmission(sourceIp: string): boolean {
  const now = Date.now();
  const current = jiraAdmissionBuckets.get(sourceIp);
  if (!current || now - current.windowStartedAt >= JIRA_PREAUTH_ABUSE_WINDOW_MS) {
    if (!current && jiraAdmissionBuckets.size >= MAX_JIRA_ADMISSION_BUCKETS) {
      const oldest = jiraAdmissionBuckets.keys().next().value;
      if (typeof oldest === 'string') jiraAdmissionBuckets.delete(oldest);
    }
    jiraAdmissionBuckets.set(sourceIp, { windowStartedAt: now, count: 1 });
    return true;
  }
  if (current.count >= JIRA_PREAUTH_ABUSE_LIMIT_PER_MINUTE) return false;
  current.count += 1;
  return true;
}

function isJiraBearerAdmissible(value: string): boolean {
  if (!/^Bearer [^\s]+$/.test(value)) return false;
  const token = value.slice('Bearer '.length);
  if (Buffer.byteLength(token, 'utf8') > MAX_JIRA_ADMISSION_TOKEN_BYTES) return false;
  const segments = token.split('.');
  if (
    segments.length !== 3 ||
    segments.some((segment) => !JIRA_ADMISSION_SEGMENT_PATTERN.test(segment))
  ) {
    return false;
  }
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  if (!encodedHeader || !encodedPayload || !encodedSignature) return false;
  const header = parseJiraAdmissionObject(encodedHeader, 8 * 1024);
  return (
    header !== null &&
    header['alg'] === 'HS256' &&
    (header['typ'] === undefined || header['typ'] === 'JWT') &&
    jiraAdmissionSegmentWithinBytes(encodedPayload, 128 * 1024) &&
    jiraAdmissionSegmentWithinBytes(encodedSignature, MAX_JIRA_ADMISSION_TOKEN_BYTES)
  );
}

function jiraAdmissionSegmentWithinBytes(segment: string, maxBytes: number): boolean {
  try {
    return Buffer.from(segment, 'base64url').byteLength <= maxBytes;
  } catch {
    return false;
  }
}

function parseJiraAdmissionObject(
  segment: string,
  maxBytes: number,
): Record<string, unknown> | null {
  let bytes: Buffer;
  try {
    bytes = Buffer.from(segment, 'base64url');
  } catch {
    return null;
  }
  if (bytes.byteLength > maxBytes) return null;
  try {
    const value: unknown = JSON.parse(bytes.toString('utf8'));
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function bearerAuthorization(
  value: string | undefined,
): { present: false } | { present: true; value: string | null } {
  if (value === undefined || !/^Bearer(?:\s|$)/i.test(value)) return { present: false };
  return /^Bearer [^\s]+$/i.test(value) ? { present: true, value } : { present: true, value: null };
}

function routeQueryValue(event: Parameters<APIGatewayProxyHandlerV2>[0]): string | null {
  const rawQueryString = event.rawQueryString;
  let rawRouteValues: string[] = [];
  if (rawQueryString !== undefined) {
    try {
      rawRouteValues = rawQueryString
        .split('&')
        .filter((part) => part.length > 0)
        .flatMap((part) => {
          const separator = part.indexOf('=');
          const rawKey = separator === -1 ? part : part.slice(0, separator);
          if (decodeURIComponent(rawKey.replace(/\+/g, ' ')) !== 'route') return [];
          const rawValue = separator === -1 ? '' : part.slice(separator + 1);
          return [decodeURIComponent(rawValue.replace(/\+/g, ' '))];
        });
    } catch {
      return null;
    }
    if (rawRouteValues.length > 1) return null;
  }

  const parameterValue = event.queryStringParameters?.['route'];
  if (rawRouteValues.length === 1 && parameterValue !== undefined) {
    if (parameterValue !== rawRouteValues[0]) return null;
  }
  const routeId = rawRouteValues[0] ?? parameterValue;
  return routeId && ROUTING_UUID_PATTERN.test(routeId) ? routeId : null;
}

function oauthDispatchContext(
  event: Parameters<APIGatewayProxyHandlerV2>[0],
  tenantId: string,
  source: string,
  routeId: string,
  authorization: string,
  headers: Record<string, string | undefined>,
): OAuthDispatchContext {
  return {
    authorization,
    method: event.requestContext?.http?.method ?? 'POST',
    rawPath: event.rawPath ?? event.requestContext?.http?.path ?? `/ingest/${tenantId}/${source}`,
    rawQuery:
      event.rawQueryString ??
      Object.entries(event.queryStringParameters ?? {})
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value ?? '')}`)
        .join('&'),
    webhookIdentifier: headers['x-atlassian-webhook-identifier'] ?? '',
    routeId,
  };
}

// A denied read and an unprovisioned secret both collapse to the same 503, so without this an IAM
// misgrant is silently indistinguishable from normal unprovisioned state.
function logSecretFetchFailure(
  scope: string,
  source: string,
  err: unknown,
  tenantId?: string,
): void {
  console.error(
    JSON.stringify({
      msg: 'dispatcher: webhook secret fetch failed',
      scope,
      source,
      ...(tenantId ? { tenantId } : {}),
      errorName: err instanceof Error ? err.name : typeof err,
    }),
  );
}

async function fetchSharedSecret(source: string): Promise<string | null> {
  const cached = secretCache.get(source);
  if (cached && Date.now() < cached.expiresAt) return cached.secret;

  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: `${SHARED_SECRET_SSM_PREFIX}/${source}`,
        WithDecryption: true,
      }),
    );
    const secret = result.Parameter?.Value ?? null;
    if (secret) {
      secretCache.set(source, { secret, expiresAt: Date.now() + CACHE_TTL_MS });
    }
    return secret;
  } catch (err) {
    logSecretFetchFailure('shared', source, err);
    return null;
  }
}

async function fetchPerTenantSecret(tenantId: string, source: string): Promise<string | null> {
  const cacheKey = `${tenantId}/${source}`;
  const cached = secretCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return cached.secret;

  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: `${PER_TENANT_SECRET_SSM_PREFIX}/${tenantId}/webhook-secrets/${source}`,
        WithDecryption: true,
      }),
    );
    const secret = result.Parameter?.Value ?? null;
    if (secret) {
      secretCache.set(cacheKey, { secret, expiresAt: Date.now() + CACHE_TTL_MS });
    }
    return secret;
  } catch (err) {
    logSecretFetchFailure('per-tenant', source, err, tenantId);
    return null;
  }
}

function isVerificationChallenge(source: string, body: unknown): boolean {
  const b = body as Record<string, unknown> | null;
  if (!b) return false;

  return source === 'slack' && b.type === 'url_verification';
}

type ChallengeResponse = { body: string; contentType: string } | null;

function handleVerificationChallenge(source: string, body: unknown): ChallengeResponse {
  const b = body as Record<string, unknown> | null;
  if (!b) return null;

  if (source === 'slack' && b.type === 'url_verification') {
    const challenge = b.challenge;
    return typeof challenge === 'string'
      ? { body: JSON.stringify({ challenge }), contentType: 'application/json' }
      : null;
  }

  return null;
}

function handleZoomCrc(source: string, body: unknown, secret: string): ChallengeResponse | null {
  if (source !== ZOOM_SOURCE) return null;
  const b = body as Record<string, unknown> | null;
  if (!b) return null;
  if (b.event !== ZOOM_URL_VALIDATION_EVENT) return null;
  const payload = b.payload as Record<string, unknown> | undefined;
  const plainToken = payload?.plainToken;
  if (typeof plainToken !== 'string') return null;
  const encryptedToken = createHmac('sha256', secret).update(plainToken).digest('hex');
  return {
    body: JSON.stringify({ plainToken, encryptedToken }),
    contentType: 'application/json',
  };
}

function isIntercomPing(body: unknown): boolean {
  if (typeof body !== 'object' || body === null) return false;
  const payload = body as Record<string, unknown>;
  if (payload['type'] !== 'notification_event' || payload['topic'] !== 'ping') return false;
  const data = payload['data'];
  if (typeof data !== 'object' || data === null) return false;
  const item = (data as Record<string, unknown>)['item'];
  return (
    typeof item === 'object' &&
    item !== null &&
    (item as Record<string, unknown>)['type'] === 'ping'
  );
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  try {
    if (event.routeKey === INTERCOM_LIVENESS_ROUTE && event.requestContext.http.method === 'HEAD') {
      return { statusCode: 204 };
    }

    const source = event.pathParameters?.['source'];
    const tenantId = event.pathParameters?.['tenant_id'];
    if (!source) return { statusCode: 400 };

    const body = event.body ?? '';
    const headers = normalizeHeaders(event.headers);
    if (source === JIRA_SOURCE && Buffer.byteLength(body, 'utf8') > MAX_JIRA_RAW_BODY_BYTES) {
      return { statusCode: 413 };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      parsed = null;
    }

    // Microsoft365 subscription validation: echo validationToken as text/plain (unsigned).
    // Must happen before the EXTRACTORS check since microsoft365 has no extractor.
    if (source === MICROSOFT365_SOURCE) {
      const validationToken = event.queryStringParameters?.['validationToken'];
      if (typeof validationToken === 'string' && validationToken.length > 0) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'text/plain' },
          body: validationToken,
        };
      }
    }

    if (!EXTRACTORS[source] && !tenantId) return { statusCode: 400 };

    if (!tenantId && source === 'notion' && isNotionVerificationChallenge(parsed)) {
      const result = await captureNotionVerificationToken(
        ssm,
        getNotionVerificationCaptureConfig(),
        parsed.verification_token,
        () => new Date(),
      );
      return result === 'captured'
        ? { statusCode: 200, headers: { 'content-type': 'text/plain' }, body: '' }
        : { statusCode: 503 };
    }

    if (isVerificationChallenge(source, parsed)) {
      const response = handleVerificationChallenge(source, parsed);
      if (response) {
        return {
          statusCode: 200,
          headers: { 'content-type': response.contentType },
          body: response.body,
        };
      }
    }

    // URL-routed mode: tenantId is in the path, use per-tenant secret, skip resolveTenant()
    if (tenantId) {
      const bearer: ReturnType<typeof bearerAuthorization> =
        source === JIRA_SOURCE ? bearerAuthorization(headers['authorization']) : { present: false };
      if (bearer.present) {
        if (
          !bearer.value ||
          headers['x-hub-signature'] !== undefined ||
          headers['x-hub-signature-256'] !== undefined
        ) {
          return { statusCode: 401 };
        }
        const routeId = routeQueryValue(event);
        if (!routeId) return { statusCode: 401 };
        if (!isJiraBearerAdmissible(bearer.value)) return { statusCode: 401 };
        const sourceIp = requestSourceIp(event);
        if (!consumeJiraAdmission(sourceIp)) return { statusCode: 429 };

        const oauthContext = oauthDispatchContext(
          event,
          tenantId,
          source,
          routeId,
          bearer.value,
          headers,
        );
        const parsedEnvelope = jiraEncryptedWebhookEnvelopeSchema.safeParse({
          version: 1,
          rawBody: body,
          authorization: oauthContext.authorization,
          method: oauthContext.method,
          rawPath: oauthContext.rawPath,
          rawQuery: oauthContext.rawQuery,
          webhookIdentifier: oauthContext.webhookIdentifier,
        });
        if (!parsedEnvelope.success) return { statusCode: 401 };
        const payloadBody = JSON.stringify(parsedEnvelope.data);
        if (
          !fitsEncryptedSqsMessage({
            tenantId,
            source,
            eventType: extractEventType(source, headers, body),
            payloadBody,
            messageType: 'jira-oauth-envelope',
          })
        ) {
          return { statusCode: 413 };
        }

        const routingDecision = await isOAuthRoutingAllowed(tenantId, source, routeId);
        if (routingDecision === 'unavailable') return { statusCode: 503 };
        if (routingDecision !== 'allowed') return { statusCode: 401 };

        const invokePayload = await buildInvokePayload(
          tenantId,
          source,
          body,
          headers,
          `${tenantId}-ingest`,
          'url',
          oauthContext,
        );
        if (!invokePayload) return { statusCode: 503 };
        const invokeResult = await lambda.send(new InvokeCommand(invokePayload));
        if (!downstreamInvokeSucceeded(invokeResult)) return { statusCode: 503 };
        return { statusCode: 200 };
      }

      if (source === JIRA_SOURCE) return { statusCode: 401 };
      const routingDecision = await isRoutingAllowed(tenantId, source, 'url');
      if (routingDecision === 'unavailable') return { statusCode: 503 };
      if (routingDecision !== 'allowed') return { statusCode: 401 };
      const secret = await fetchPerTenantSecret(tenantId, source);
      if (!secret) return { statusCode: 503 };

      const signatureValid = verifySignature(source, headers, body, secret);
      if (!signatureValid) return { statusCode: 401 };

      // Zoom CRC: handle endpoint.url_validation AFTER signature verification
      const zoomCrc = handleZoomCrc(source, parsed, secret);
      if (zoomCrc) {
        return {
          statusCode: 200,
          headers: { 'content-type': zoomCrc.contentType },
          body: zoomCrc.body,
        };
      }

      // Rate limiting (skip if RATE_LIMIT_TABLE env var is not configured)
      const rateLimitTable = process.env['RATE_LIMIT_TABLE'];
      if (rateLimitTable) {
        if (!(await checkRateLimit(tenantId, source))) {
          return { statusCode: 429 };
        }
      }

      const invokePayload = await buildInvokePayload(
        tenantId,
        source,
        body,
        headers,
        `${tenantId}-ingest`,
        'url',
      );
      if (!invokePayload) return { statusCode: 503 };
      const invokeResult = await lambda.send(new InvokeCommand(invokePayload));
      if (!downstreamInvokeSucceeded(invokeResult)) return { statusCode: 503 };

      return { statusCode: 200 };
    }

    // Shared-secret mode: use shared secret for signature verification
    const secret = await fetchSharedSecret(source);
    if (!secret) return { statusCode: 503 };

    const signatureValid = verifySignature(source, headers, body, secret);
    if (!signatureValid) return { statusCode: 401 };

    if (source === INTERCOM_SOURCE && isIntercomPing(parsed)) {
      return { statusCode: 200 };
    }

    // Zoom CRC: handle endpoint.url_validation AFTER signature verification
    const zoomCrc = handleZoomCrc(source, parsed, secret);
    if (zoomCrc) {
      return {
        statusCode: 200,
        headers: { 'content-type': zoomCrc.contentType },
        body: zoomCrc.body,
      };
    }

    const tenant = await resolveTenant(ddb, source, parsed, headers as Record<string, string>);
    if (!tenant) return { statusCode: 401 };
    const routingDecision = await isRoutingAllowed(tenant.orgId, source, 'payload');
    if (routingDecision === 'unavailable') return { statusCode: 503 };
    if (routingDecision !== 'allowed') return { statusCode: 401 };

    // Rate limiting (skip if RATE_LIMIT_TABLE env var is not configured)
    const rateLimitTable = process.env['RATE_LIMIT_TABLE'];
    if (rateLimitTable) {
      if (!(await checkRateLimit(tenant.orgId, source))) {
        return { statusCode: 429 };
      }
    }

    const invokePayload = await buildInvokePayload(
      tenant.orgId,
      source,
      body,
      headers,
      `${tenant.orgId}-ingest`,
      'payload',
    );
    if (!invokePayload) return { statusCode: 503 };
    const invokeResult = await lambda.send(new InvokeCommand(invokePayload));
    if (!downstreamInvokeSucceeded(invokeResult)) return { statusCode: 503 };

    return { statusCode: 200 };
  } catch (err) {
    const source = event.pathParameters?.['source'] ?? 'unknown';
    console.error(
      JSON.stringify({
        msg: 'dispatcher: unhandled error',
        source,
        errorName: err instanceof Error ? err.name : typeof err,
      }),
    );
    return { statusCode: 500 };
  }
};

function requestSourceIp(event: Parameters<APIGatewayProxyHandlerV2>[0]): string {
  const context = event.requestContext as unknown as {
    http?: { sourceIp?: unknown };
    identity?: { sourceIp?: unknown };
  };
  const value = context.http?.sourceIp ?? context.identity?.sourceIp;
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= MAX_RATE_LIMIT_ID_BYTES
    ? value
    : 'unknown';
}
