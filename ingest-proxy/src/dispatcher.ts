import { createHmac } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { resolveTenant, EXTRACTORS } from './tenant-resolver.js';
import { verifySignature, normalizeHeaders } from './signature-verifier.js';
import { extractEventType } from './lambdas/handler.js';
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
  verifyRoutingHmac,
  type RoutingMode,
} from './routing-allowlist.js';

const ssm = new SSMClient({});
const ddb = new DynamoDBClient({});
const lambda = new LambdaClient({});

const CACHE_TTL_MS = 5 * 60 * 1000;
const secretCache = new Map<string, { secret: string; expiresAt: number }>();
const allowlistCache = new Map<
  string,
  { entries: ReturnType<typeof normalizeRoutingAllowlist>; expiresAt: number }
>();

const SHARED_SECRET_SSM_PREFIX = '/folklore/shared-webhook-secrets';
const PER_TENANT_SECRET_SSM_PREFIX = '/folklore';
const ZOOM_SOURCE = 'zoom';
const ZOOM_URL_VALIDATION_EVENT = 'endpoint.url_validation';
const MICROSOFT365_SOURCE = 'microsoft365';
const INTERCOM_SOURCE = 'intercom';
const INTERCOM_LIVENESS_ROUTE = 'HEAD /ingest/intercom';

// Returns null (never invokes downstream) when the shared auth secret isn't provisioned,
// rather than sending an invoke the receiving ingest Lambda is guaranteed to reject.
async function buildInvokePayload(
  destTenantId: string,
  destSource: string,
  destBody: string,
  destHeaders: Record<string, string | undefined>,
  destFunctionName: string,
  mode: RoutingMode,
): Promise<{ FunctionName: string; InvocationType: 'Event'; Payload: Buffer } | null> {
  const secret = await fetchDispatcherAuthSecret();
  if (!secret) return null;

  return {
    FunctionName: destFunctionName,
    InvocationType: 'Event' as const,
    Payload: Buffer.from(
      JSON.stringify({
        source: destSource,
        body: destBody,
        tenantId: destTenantId,
        deliveryId: destHeaders['x-github-delivery'] ?? destHeaders['webhook-id'] ?? '',
        authHmac: computeDispatcherAuthHmac(destTenantId, destSource, secret, mode),
        routingMode: mode,
        eventType: extractEventType(destSource, destHeaders, destBody),
        headers: destHeaders,
      }),
    ),
  };
}

async function fetchRoutingAllowlist(
  orgId: string,
): Promise<ReturnType<typeof normalizeRoutingAllowlist>> {
  const cached = allowlistCache.get(orgId);
  if (cached && Date.now() < cached.expiresAt) return cached.entries;
  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: `/folklore/${orgId}/webhook-routing-allowlist`,
        WithDecryption: false,
      }),
    );
    const parsed: unknown = JSON.parse(result.Parameter?.Value ?? '[]');
    const entries = normalizeRoutingAllowlist(parsed);
    allowlistCache.set(orgId, { entries, expiresAt: Date.now() + CACHE_TTL_MS });
    return entries;
  } catch {
    return [];
  }
}

type RoutingDecision = 'allowed' | 'denied' | 'unavailable';

async function isRoutingAllowed(
  orgId: string,
  source: string,
  mode: RoutingMode,
): Promise<RoutingDecision> {
  const entries = await fetchRoutingAllowlist(orgId);
  const entry = findRoutingAllowlistEntry(entries, orgId, source, mode);
  if (!entry?.hmac) return 'denied';
  const secret = await fetchPerTenantSecret(orgId, source);
  if (!secret) return 'unavailable';
  const expected = createHmac('sha256', secret).update(`${orgId}:${source}:${mode}`).digest('hex');
  return verifyRoutingHmac(expected, entry.hmac, entry.previousHmac) ? 'allowed' : 'denied';
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
      await lambda.send(new InvokeCommand(invokePayload));

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
    await lambda.send(new InvokeCommand(invokePayload));

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
