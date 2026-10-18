import { createHash } from 'node:crypto';

export const EDGE_LANE_BUCKETS = 16;
export const EDGE_LANE_DOMAIN = 'folklore.edge-lane.v1';

const JIRA_OAUTH_ENVELOPE = 'jira-oauth-envelope';
const SOURCE_WIDE_LANE = '';
const KEY_SEPARATOR = '\0';
const BUCKET_PREFIX_BYTES = 4;

type ItemKeyReader = (payload: unknown) => string;

function field(value: unknown, ...path: string[]): unknown {
  let current = value;
  for (const key of path) {
    if (typeof current !== 'object' || current === null || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function scalar(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : '';
}

function githubItemKey(payload: unknown): string {
  const repositoryId = scalar(field(payload, 'repository', 'id'));
  const number =
    scalar(field(payload, 'pull_request', 'number')) || scalar(field(payload, 'issue', 'number'));
  return `${repositoryId}#${number}`;
}

function slackItemKey(payload: unknown): string {
  return (
    scalar(field(payload, 'event', 'channel')) || scalar(field(payload, 'event', 'item', 'channel'))
  );
}

function jiraItemKey(payload: unknown): string {
  return scalar(field(payload, 'issue', 'key'));
}

// A source with no entry, Linear among them, shares one bucket per tenant and its body is never parsed.
const ITEM_KEY_READERS: ReadonlyMap<string, ItemKeyReader> = new Map([
  ['github', githubItemKey],
  ['slack', slackItemKey],
  ['jira', jiraItemKey],
]);

function parsePayload(payloadBody: string): unknown {
  try {
    const parsed: unknown = JSON.parse(payloadBody);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? parsed
      : undefined;
  } catch {
    return undefined;
  }
}

/** The item a webhook belongs to, chosen so every event on one item shares a lane. Only ever hashed. */
export function edgeLaneItemKey(source: string, payloadBody: string, messageType?: string): string {
  // The OAuth envelope wraps the provider's raw body, which this edge does not read.
  if (messageType === JIRA_OAUTH_ENVELOPE) return SOURCE_WIDE_LANE;
  const readItemKey = ITEM_KEY_READERS.get(source);
  if (readItemKey === undefined) return SOURCE_WIDE_LANE;
  const payload = parsePayload(payloadBody);
  return payload === undefined ? SOURCE_WIDE_LANE : readItemKey(payload);
}

/** FIFO group id: the tenant plus a bucket from an unkeyed hash, so it reveals at most four bits of the item. */
export function edgeLaneGroupId(
  tenantId: string,
  source: string,
  payloadBody: string,
  messageType?: string,
): string {
  const itemKey = edgeLaneItemKey(source, payloadBody, messageType);
  const digest = createHash('sha256')
    .update([EDGE_LANE_DOMAIN, tenantId, source, itemKey].join(KEY_SEPARATOR))
    .digest();
  return `${tenantId}:${digest.readUIntBE(0, BUCKET_PREFIX_BYTES) % EDGE_LANE_BUCKETS}`;
}
