import { createHmac } from 'crypto';
import {
  CONNECTOR_MANIFESTS,
  isDeclarativeWebhook,
  webhookEventTypeSchema,
  type ConnectorWebhook,
  type WebhookSelector,
  type WebhookVerifier,
} from '@folklore/contracts';
import { resolveJsonPointer } from '@folklore/utils/json-pointer';
import {
  decodeBase64,
  decodeHex,
  matchesDigest,
  verifySignature,
  verifySvixSignature,
  withinReplayWindow,
} from './signature-verifier.js';

type Headers = Record<string, string | undefined>;
type HmacBodyVerifier = Extract<WebhookVerifier, { scheme: 'hmac_body' }>;
type TimestampedVerifier = Extract<WebhookVerifier, { scheme: 'hmac_timestamped' }>;

export const MAX_SELECTED_VALUE_BYTES = 128;

export const WEBHOOKS: ReadonlyMap<string, ConnectorWebhook> = new Map(
  CONNECTOR_MANIFESTS.flatMap((manifest): [string, ConnectorWebhook][] =>
    manifest.webhook === null ? [] : [[manifest.kind, manifest.webhook]],
  ),
);

const TIMESTAMPED_PREFIX = 'v0=';
const TIMESTAMPED_VERSION = 'v0';

function header(headers: Headers, name: string): string | undefined {
  return Object.hasOwn(headers, name) ? headers[name] : undefined;
}

function verifyHmacBody(
  verifier: HmacBodyVerifier,
  headers: Headers,
  body: string,
  secret: string,
): boolean {
  const provided = header(headers, verifier.header);
  const prefix = verifier.prefix ?? '';
  if (provided === undefined || !provided.startsWith(prefix)) return false;
  const digest = provided.slice(prefix.length);
  const decoded = verifier.encoding === 'hex' ? decodeHex(digest) : decodeBase64(digest);
  const computed = createHmac(verifier.algorithm, secret).update(body, 'utf8').digest();
  return matchesDigest(decoded, computed);
}

function verifyHmacTimestamped(
  verifier: TimestampedVerifier,
  headers: Headers,
  body: string,
  secret: string,
): boolean {
  const provided = header(headers, verifier.header);
  const timestamp = header(headers, verifier.timestampHeader);
  if (provided === undefined || !provided.startsWith(TIMESTAMPED_PREFIX)) return false;
  if (!withinReplayWindow(timestamp, verifier.toleranceSeconds)) return false;
  const decoded = decodeHex(provided.slice(TIMESTAMPED_PREFIX.length));
  const computed = createHmac('sha256', secret)
    .update(`${TIMESTAMPED_VERSION}:${timestamp}:${body}`, 'utf8')
    .digest();
  return matchesDigest(decoded, computed);
}

export function verifyByDescriptor(
  verifier: WebhookVerifier,
  headers: Headers,
  body: string,
  secret: string,
): boolean {
  switch (verifier.scheme) {
    case 'hmac_body':
      return verifyHmacBody(verifier, headers, body, secret);
    case 'hmac_timestamped':
      return verifyHmacTimestamped(verifier, headers, body, secret);
    case 'svix':
      return verifySvixSignature(headers, body, secret);
    case 'builtin':
      return false;
  }
}

export function selectValue(
  selector: WebhookSelector,
  headers: Headers,
  parsedBody: unknown,
): string {
  if (selector === null) return '';
  const value =
    selector.from === 'header'
      ? header(headers, selector.name)
      : resolveJsonPointer(parsedBody, selector.pointer);
  const isScalar =
    typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value));
  if (!isScalar) return '';
  const text = String(value);
  return Buffer.byteLength(text, 'utf8') <= MAX_SELECTED_VALUE_BYTES ? text : '';
}

export function selectEventType(
  selector: WebhookSelector,
  headers: Headers,
  parsedBody: unknown,
): string {
  const value = selectValue(selector, headers, parsedBody);
  return webhookEventTypeSchema.safeParse(value).success ? value : '';
}

export function verifyDelivery(
  webhooks: ReadonlyMap<string, ConnectorWebhook>,
  source: string,
  headers: Headers,
  body: string,
  secret: string,
): boolean {
  const webhook = webhooks.get(source);
  if (webhook === undefined || !isDeclarativeWebhook(webhook)) {
    return verifySignature(source, headers, body, secret);
  }
  return verifyByDescriptor(webhook.verifier, headers, body, secret);
}
