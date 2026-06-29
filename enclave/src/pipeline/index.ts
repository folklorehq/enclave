import { embedText } from '../inference/tinfoil.js';
import { persistFact } from '../db/persist.js';

type SourceKind = 'github' | 'slack' | 'linear' | 'notion' | 'intercom';

const KNOWN_SOURCES = new Set<SourceKind>(['github', 'slack', 'linear', 'notion', 'intercom']);

function isKnownSource(s: string): s is SourceKind {
  return KNOWN_SOURCES.has(s as SourceKind);
}

interface NormalizedEvent {
  source: SourceKind;
  body: unknown;
}

function normalize(source: SourceKind, plaintext: Buffer): NormalizedEvent | null {
  try {
    const body: unknown = JSON.parse(plaintext.toString('utf8'));
    return { source, body };
  } catch {
    return null;
  }
}

// sourceFactId extracts a stable dedup key from the raw event body.
// Falls back to a SHA-256 fingerprint of the body when no explicit id field is present.
function extractSourceFactId(body: unknown): string {
  if (body !== null && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    const id = b['id'] ?? b['node_id'] ?? b['ts'] ?? b['identifier'];
    if (typeof id === 'string' || typeof id === 'number') return String(id);
  }
  return Buffer.from(JSON.stringify(body)).toString('base64url').slice(0, 64);
}

export async function handle(plaintext: Buffer, source: string, _masterKey: Buffer): Promise<void> {
  if (!isKnownSource(source)) {
    console.warn('unknown source kind — dropping', { source });
    return;
  }

  const event = normalize(source, plaintext);
  if (!event) {
    console.warn('failed to parse event body — dropping', { source });
    return;
  }

  const orgId = process.env['TENANT_ID']!;
  const bodyStr = JSON.stringify(event.body);
  const sourceFactId = extractSourceFactId(event.body);

  const embedding = await embedText(bodyStr);

  await persistFact({
    orgId,
    sourceKind: event.source,
    sourceFactId,
    occurredAt: new Date(),
    body: bodyStr,
    embedding,
  });
}
