type SourceKind = 'github' | 'slack' | 'linear' | 'notion' | 'intercom';

const KNOWN_SOURCES = new Set<SourceKind>(['github', 'slack', 'linear', 'notion', 'intercom']);

function isKnownSource(s: string): s is SourceKind {
  return KNOWN_SOURCES.has(s as SourceKind);
}

interface NormalizedEvent {
  source: SourceKind;
  // unknown until full Fact/Container normalization is implemented
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

  // TODO: embed via Tinfoil confidential inference
  // TODO: score associations
  // TODO: persist Fact/Container + embedding + graph edges to Postgres + Memgraph
}
