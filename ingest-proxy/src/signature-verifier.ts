import { createHmac, timingSafeEqual } from 'crypto';
import type { WebhookTimestampUnit } from '@folklore/contracts';

const MS_PER_S = 1000;
const SLACK_REPLAY_TOLERANCE_S = 300;
const ZOOM_REPLAY_TOLERANCE_S = 300;
const HEX_PATTERN = /^[0-9a-f]+$/i;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function normalizeHeaders(
  headers: Record<string, string | undefined> | undefined,
): Record<string, string | undefined> {
  // Relays may preserve provider header casing, so normalize once before lookup.
  const normalized: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

function timestampSeconds(timestamp: unknown, unit: WebhookTimestampUnit): number {
  const value =
    typeof timestamp === 'number' || typeof timestamp === 'string' ? Number(timestamp) : NaN;
  return unit === 'ms' ? value / MS_PER_S : value;
}

export function withinReplayWindow(
  timestamp: unknown,
  toleranceS: number,
  unit: WebhookTimestampUnit = 's',
  nowMs: number = Date.now(),
): boolean {
  // The signed basestring includes the timestamp, so this bounds replay; non-numeric timestamps fail closed.
  const seconds = timestampSeconds(timestamp, unit);
  return Number.isFinite(seconds) && Math.abs(nowMs / MS_PER_S - seconds) <= toleranceS;
}

export function decodeHex(value: string): Buffer | null {
  if (value.length === 0 || value.length % 2 !== 0 || !HEX_PATTERN.test(value)) return null;
  return Buffer.from(value, 'hex');
}

export function decodeBase64(value: string): Buffer | null {
  if (value.length === 0 || !BASE64_PATTERN.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64').replace(/=+$/, '') === value.replace(/=+$/, '')
    ? decoded
    : null;
}

export function matchesDigest(provided: Buffer | null, expected: Buffer): boolean {
  return (
    provided !== null && provided.length === expected.length && timingSafeEqual(provided, expected)
  );
}

type SignatureVerifier = (
  headers: Record<string, string | undefined>,
  body: string,
  secret: string,
) => boolean;

const signatureVerifiers: Record<string, SignatureVerifier> = {
  github: (headers, body, secret) => {
    const sig = headers['x-hub-signature-256'];
    if (!sig?.startsWith('sha256=')) return false;
    const expected = decodeHex(sig.slice(7));
    const computed = createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  slack: (headers, body, secret) => {
    const sig = headers['x-slack-signature'];
    const ts = headers['x-slack-request-timestamp'];
    if (!sig?.startsWith('v0=')) return false;
    if (!withinReplayWindow(ts, SLACK_REPLAY_TOLERANCE_S)) return false;
    const basestring = `v0:${ts}:${body}`;
    const expected = decodeHex(sig.slice(3));
    const computed = createHmac('sha256', secret).update(basestring, 'utf8').digest();
    return matchesDigest(expected, computed);
  },
  linear: (headers, body, secret) => {
    const sig = headers['linear-signature'];
    if (!sig) return false;
    const expected = decodeHex(sig);
    const computed = createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  intercom: (headers, body, secret) => {
    const sig = headers['x-hub-signature'];
    if (!sig?.startsWith('sha1=')) return false;
    const expected = decodeHex(sig.slice(5));
    const computed = createHmac('sha1', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  jira: (headers, body, secret) => {
    // Jira and Intercom share X-Hub-Signature; the source path disambiguates SHA-256 from SHA-1.
    const sig = headers['x-hub-signature'];
    if (!sig?.startsWith('sha256=')) return false;
    const expected = decodeHex(sig.slice(7));
    const computed = createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  notion: (headers, body, secret) => {
    // Notion signs with the subscription verification_token, not an app secret.
    const sig = headers['x-notion-signature'];
    if (!sig?.startsWith('sha256=')) return false;
    const expected = decodeHex(sig.slice(7));
    const computed = createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  zoom: (headers, body, secret) => {
    // The timestamp is part of Zoom's signed basestring, so it also bounds replay.
    const sig = headers['x-zm-signature'];
    const ts = headers['x-zm-request-timestamp'];
    if (!sig?.startsWith('v0=')) return false;
    if (!withinReplayWindow(ts, ZOOM_REPLAY_TOLERANCE_S)) return false;
    const basestring = `v0:${ts}:${body}`;
    const expected = decodeHex(sig.slice(3));
    const computed = createHmac('sha256', secret).update(basestring, 'utf8').digest();
    return matchesDigest(expected, computed);
  },
};

export const SIGNATURE_VERIFIER_SOURCES = Object.freeze(Object.keys(signatureVerifiers));

export function verifySignature(
  source: string,
  headers: Record<string, string | undefined>,
  body: string,
  secret: string,
): boolean {
  if (!Object.hasOwn(signatureVerifiers, source)) return false;
  return signatureVerifiers[source]?.(headers, body, secret) ?? false;
}
