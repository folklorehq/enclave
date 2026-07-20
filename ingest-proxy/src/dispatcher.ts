import { createHmac } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { resolveTenant, EXTRACTORS } from './tenant-resolver.js';
import { verifySignature, normalizeHeaders } from './signature-verifier.js';
import { extractEventType } from './lambdas/handler.js';
import { checkRateLimit } from './rate-limiter.js';

const ssm = new SSMClient({});
const ddb = new DynamoDBClient({});
const lambda = new LambdaClient({});

const CACHE_TTL_MS = 5 * 60 * 1000;
const secretCache = new Map<string, { secret: string; expiresAt: number }>();

const SHARED_SECRET_SSM_PREFIX = '/folklore/shared-webhook-secrets';
const PER_TENANT_SECRET_SSM_PREFIX = '/folklore';
const ZOOM_SOURCE = 'zoom';
const ZOOM_URL_VALIDATION_EVENT = 'endpoint.url_validation';
const MICROSOFT365_SOURCE = 'microsoft365';

const VERIFICATION_CHALLENGE_SOURCES = new Set(['slack', 'notion']);

const DISPATCHER_AUTH_SECRET = process.env['DISPATCHER_AUTH_SECRET'] ?? '';

function dispatcherAuthHmac(tenantId: string, source: string): string {
  return createHmac('sha256', DISPATCHER_AUTH_SECRET).update(`${tenantId}:${source}`).digest('hex');
}

function buildInvokePayload(
  destTenantId: string,
  destSource: string,
  destBody: string,
  destHeaders: Record<string, string | undefined>,
  destFunctionName: string,
): { FunctionName: string; InvocationType: 'Event'; Payload: Buffer } {
  return {
    FunctionName: destFunctionName,
    InvocationType: 'Event' as const,
    Payload: Buffer.from(
      JSON.stringify({
        source: destSource,
        body: destBody,
        tenantId: destTenantId,
        deliveryId: destHeaders['x-github-delivery'] ?? destHeaders['webhook-id'] ?? '',
        authHmac: dispatcherAuthHmac(destTenantId, destSource),
        eventType: extractEventType(destSource, destHeaders, destBody),
        headers: destHeaders,
      }),
    ),
  };
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
  } catch {
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
  } catch {
    return null;
  }
}

function isVerificationChallenge(
  source: string,
  body: unknown,
  headers: Record<string, string | undefined>,
): boolean {
  if (!VERIFICATION_CHALLENGE_SOURCES.has(source)) return false;
  const b = body as Record<string, unknown> | null;
  if (!b) return false;

  if (source === 'slack' && b.type === 'url_verification') return true;
  if (source === 'notion' && typeof b.verification_token === 'string' && b.type === undefined) {
    // If x-notion-signature is present, it is a real signed event, not a handshake.
    if (headers['x-notion-signature']) return false;
    return true;
  }
  return false;
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

  // Notion handshake has no secret, just return HTTP 200 with empty body
  if (source === 'notion') {
    return { body: '', contentType: 'text/plain' };
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

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
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

  // Check verification challenges BEFORE signature verification (Slack, Notion handshake)
  if (isVerificationChallenge(source, parsed, headers)) {
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

    const perTenantFunctionName = `${tenantId}-ingest`;
    await lambda.send(
      new InvokeCommand({
        FunctionName: perTenantFunctionName,
        InvocationType: 'Event',
        Payload: Buffer.from(
          JSON.stringify({
            source,
            body,
            tenantId,
            deliveryId: headers['x-github-delivery'] ?? headers['webhook-id'] ?? '',
          }),
        ),
      }),
    );

    return { statusCode: 200 };
  }

  // Shared-secret mode: use shared secret for signature verification
  const secret = await fetchSharedSecret(source);
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

  const tenant = await resolveTenant(ddb, source, parsed, headers as Record<string, string>);
  if (!tenant) return { statusCode: 401 };

  // Rate limiting (skip if RATE_LIMIT_TABLE env var is not configured)
  const rateLimitTable = process.env['RATE_LIMIT_TABLE'];
  if (rateLimitTable) {
    if (!(await checkRateLimit(tenant.orgId, source))) {
      return { statusCode: 429 };
    }
  }

  const perTenantFunctionName = `${tenant.orgId}-ingest`;
  await lambda.send(
    new InvokeCommand({
      FunctionName: perTenantFunctionName,
      InvocationType: 'Event',
      Payload: Buffer.from(
        JSON.stringify({
          source,
          body,
          tenantId: tenant.orgId,
          deliveryId: headers['x-github-delivery'] ?? headers['webhook-id'] ?? '',
          authHmac: dispatcherAuthHmac(tenant.orgId, source),
        }),
      ),
    }),
  );

  return { statusCode: 200 };
};
