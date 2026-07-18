import { GetItemCommand } from '@aws-sdk/client-dynamodb';
import type { DynamoDBClient } from '@aws-sdk/client-dynamodb';

export interface TenantResolution {
  orgId: string;
  resolvedFrom: 'payload' | 'jwt' | 'dynamic';
}

export type ExtractorFn = (body: unknown, headers: Record<string, string>) => string | null;

interface RoutingEntry {
  orgId: string;
  functionName: string;
}

const ROUTING_TABLE = process.env['WEBHOOK_ROUTING_TABLE'] ?? '';
const CACHE_TTL_MS = 60_000;
const routingCache = new Map<string, { entry: RoutingEntry; expiresAt: number }>();

async function fetchRoutingEntry(
  ddb: DynamoDBClient,
  source: string,
  externalId: string,
): Promise<RoutingEntry | null> {
  const cacheKey = `${source}#${externalId}`;
  const cached = routingCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) return cached.entry;

  if (!ROUTING_TABLE) return null;

  const out = await ddb.send(
    new GetItemCommand({
      TableName: ROUTING_TABLE,
      Key: { routingKey: { S: cacheKey } },
      ProjectionExpression: 'orgId,functionName',
    }),
  );

  const item = out.Item;
  if (!item?.orgId?.S) return null;

  const entry: RoutingEntry = {
    orgId: item.orgId.S,
    functionName: item.functionName?.S ?? '',
  };
  routingCache.set(cacheKey, { entry, expiresAt: Date.now() + CACHE_TTL_MS });
  return entry;
}

export function clearRoutingCache(): void {
  routingCache.clear();
}

const githubExtractor: ExtractorFn = (body) => {
  const b = body as Record<string, unknown> | null;
  const inst = b?.installation as Record<string, unknown> | undefined;
  return inst?.id != null ? String(inst.id) : null;
};

const slackExtractor: ExtractorFn = (body) => {
  const b = body as Record<string, unknown> | null;
  if (b?.type === 'url_verification') return null;
  const teamId = b?.team_id;
  return typeof teamId === 'string' ? teamId : null;
};

const linearExtractor: ExtractorFn = (body) => {
  const b = body as Record<string, unknown> | null;
  const orgId = b?.organizationId;
  return typeof orgId === 'string' ? orgId : null;
};

const notionExtractor: ExtractorFn = (body) => {
  const b = body as Record<string, unknown> | null;
  const wsId = b?.workspace_id;
  return typeof wsId === 'string' ? wsId : null;
};

const zoomExtractor: ExtractorFn = (body) => {
  const b = body as Record<string, unknown> | null;
  if (b?.event === 'endpoint.url_validation') return null;
  const payload = b?.payload as Record<string, unknown> | undefined;
  const accountId = payload?.account_id;
  return typeof accountId === 'string' ? accountId : null;
};

const intercomExtractor: ExtractorFn = (body) => {
  const b = body as Record<string, unknown> | null;
  const appId = b?.app_id;
  return typeof appId === 'string' ? appId : null;
};

function jwtIssExtractor(_body: unknown, headers: Record<string, string>): string | null {
  const auth = headers['authorization'];
  if (!auth?.toLowerCase().startsWith('jwt ')) return null;
  try {
    const payloadB64 = auth.slice(4).trim().split('.')[1];
    if (!payloadB64) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const iss = payload['iss'];
    return typeof iss === 'string' ? iss : null;
  } catch {
    return null;
  }
}

export const EXTRACTORS: Record<string, ExtractorFn> = {
  github: githubExtractor,
  slack: slackExtractor,
  linear: linearExtractor,
  notion: notionExtractor,
  zoom: zoomExtractor,
  intercom: intercomExtractor,
  jira: jwtIssExtractor,
  confluence: jwtIssExtractor,
};

export async function resolveTenant(
  ddb: DynamoDBClient,
  source: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<{ orgId: string; functionName: string } | null> {
  const extractor = EXTRACTORS[source];
  if (!extractor) return null;

  const externalId = extractor(body, headers);
  if (!externalId) return null;

  const entry = await fetchRoutingEntry(ddb, source, externalId);
  if (!entry) return null;

  return { orgId: entry.orgId, functionName: entry.functionName };
}
