import { createHmac, timingSafeEqual } from 'crypto';

const SVIX_SECRET_PREFIX = 'whsec_';
const CONNECT_JWT_PREFIX = 'jwt ';
const JWT_CLOCK_SKEW_S = 60;
const MS_PER_S = 1000;
const SLACK_REPLAY_TOLERANCE_S = 300;
const SVIX_REPLAY_TOLERANCE_S = 300;
const ZOOM_REPLAY_TOLERANCE_S = 300;
const HEX_PATTERN = /^[0-9a-f]+$/i;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

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

function withinReplayWindow(ts: string | undefined, toleranceS: number): boolean {
  // The signed basestring includes the timestamp, so this bounds replay; non-numeric timestamps fail closed.
  const tsNum = Number(ts);
  return Number.isFinite(tsNum) && Math.abs(Date.now() / MS_PER_S - tsNum) <= toleranceS;
}

function decodeJwtSegment(segment: string): Record<string, unknown> | null {
  const decoded = decodeBase64Url(segment);
  if (!decoded) return null;
  try {
    return JSON.parse(decoded.toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function decodeHex(value: string): Buffer | null {
  if (value.length === 0 || value.length % 2 !== 0 || !HEX_PATTERN.test(value)) return null;
  return Buffer.from(value, 'hex');
}

function decodeBase64(value: string): Buffer | null {
  if (value.length === 0 || !BASE64_PATTERN.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64').replace(/=+$/, '') === value.replace(/=+$/, '')
    ? decoded
    : null;
}

function decodeBase64Url(value: string): Buffer | null {
  if (value.length === 0 || value.length % 4 === 1 || !BASE64URL_PATTERN.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value ? decoded : null;
}

function matchesDigest(provided: Buffer | null, expected: Buffer): boolean {
  return (
    provided !== null && provided.length === expected.length && timingSafeEqual(provided, expected)
  );
}

// qsh is intentionally unchecked because canonical request reconstruction behind API Gateway is brittle. The per-tenant secret lookup supplies iss/clientKey tenant binding.
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
  const provided = decodeBase64Url(signatureB64);
  if (!matchesDigest(provided, expected)) return false;

  const payload = decodeJwtSegment(payloadB64);
  if (!payload) return false;
  const exp = payload['exp'];
  const now = Math.floor(Date.now() / MS_PER_S);
  if (typeof exp !== 'number' || now > exp + JWT_CLOCK_SKEW_S) return false;
  return true;
}

function svixKey(secret: string): Buffer | null {
  const raw = secret.startsWith(SVIX_SECRET_PREFIX)
    ? secret.slice(SVIX_SECRET_PREFIX.length)
    : secret;
  return decodeBase64(raw);
}

export function verifySvixSignature(
  headers: Record<string, string | undefined>,
  body: string,
  secret: string,
): boolean {
  const id = headers['webhook-id'] ?? headers['svix-id'];
  const ts = headers['webhook-timestamp'] ?? headers['svix-timestamp'];
  const sigHeader = headers['webhook-signature'] ?? headers['svix-signature'];
  if (!id || !ts || !sigHeader) return false;
  if (!withinReplayWindow(ts, SVIX_REPLAY_TOLERANCE_S)) return false;

  const key = svixKey(secret);
  if (!key) return false;
  const expected = createHmac('sha256', key).update(`${id}.${ts}.${body}`, 'utf8').digest();

  for (const token of sigHeader.split(' ')) {
    if (!token.startsWith('v1,')) continue;
    const provided = decodeBase64(token.slice('v1,'.length));
    if (matchesDigest(provided, expected)) return true;
  }
  return false;
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
  confluence: (headers, _body, secret) => {
    // The app-install secret signs the JWT, so body-HMAC verification would be incorrect.
    return verifyConnectJwt(headers['authorization'], secret);
  },
  notion: (headers, body, secret) => {
    // Notion signs with the subscription verification_token, not an app secret.
    const sig = headers['x-notion-signature'];
    if (!sig?.startsWith('sha256=')) return false;
    const expected = decodeHex(sig.slice(7));
    const computed = createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  meeting: (headers, body, secret) => {
    const sig = headers['x-meeting-signature'];
    if (!sig?.startsWith('sha256=')) return false;
    const expected = decodeHex(sig.slice(7));
    const computed = createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest();
    return matchesDigest(expected, computed);
  },
  zoom_bot: (headers, body, secret) => verifySvixSignature(headers, body, secret),
  google_drive: (headers, _body, secret) => {
    // Drive push has no body signature; the channel token set at watch time is the gate.
    const token = headers['x-goog-channel-token'];
    if (!token) return false;
    const expected = Buffer.from(secret, 'utf8');
    const provided = Buffer.from(token, 'utf8');
    return matchesDigest(provided, expected);
  },
  microsoft365: (_headers, body, secret) => {
    // Graph has no body HMAC; every notification must carry the subscription clientState.
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
      return matchesDigest(provided, expected);
    });
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
  return signatureVerifiers[source]?.(headers, body, secret) ?? false;
}
