import { createHmac, timingSafeEqual } from 'crypto';

const SVIX_SECRET_PREFIX = 'whsec_';
const CONNECT_JWT_PREFIX = 'jwt ';
const JWT_CLOCK_SKEW_S = 60;
const MS_PER_S = 1000;
const SLACK_REPLAY_TOLERANCE_S = 300;
const SVIX_REPLAY_TOLERANCE_S = 300;
const ZOOM_REPLAY_TOLERANCE_S = 300;

export function normalizeHeaders(
  headers: Record<string, string | undefined> | undefined,
): Record<string, string | undefined> {
  const normalized: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

export function withinReplayWindow(ts: string | undefined, toleranceS: number): boolean {
  const tsNum = Number(ts);
  return Number.isFinite(tsNum) && Math.abs(Date.now() / MS_PER_S - tsNum) <= toleranceS;
}

export function decodeJwtSegment(segment: string): Record<string, unknown> | null {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
  } catch {
    return null;
  }
}

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

function svixKey(secret: string): Buffer {
  const raw = secret.startsWith(SVIX_SECRET_PREFIX)
    ? secret.slice(SVIX_SECRET_PREFIX.length)
    : secret;
  return Buffer.from(raw, 'base64');
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

export function verifySignature(
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
      const sig = headers['linear-signature'];
      if (!sig) return false;
      const expected = Buffer.from(sig, 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'intercom': {
      const sig = headers['x-hub-signature'];
      if (!sig?.startsWith('sha1=')) return false;
      const expected = Buffer.from(sig.slice(5), 'hex');
      const computed = createHmac('sha1', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'jira': {
      const sig = headers['x-hub-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'confluence': {
      return verifyConnectJwt(headers['authorization'], secret);
    }

    case 'notion': {
      const sig = headers['x-notion-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'meeting': {
      const sig = headers['x-meeting-signature'];
      if (!sig?.startsWith('sha256=')) return false;
      const expected = Buffer.from(sig.slice(7), 'hex');
      const computed = createHmac('sha256', secret).update(bodyBuf).digest();
      return expected.length === computed.length && timingSafeEqual(expected, computed);
    }

    case 'zoom_bot':
      return verifySvixSignature(headers, body, secret);

    case 'google_drive': {
      const token = headers['x-goog-channel-token'];
      if (!token) return false;
      const expected = Buffer.from(secret, 'utf8');
      const provided = Buffer.from(token, 'utf8');
      return expected.length === provided.length && timingSafeEqual(expected, provided);
    }

    case 'microsoft365': {
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
      return false;
  }
}
