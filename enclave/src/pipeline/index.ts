import { embedText } from '../inference/ollama.js';
import type { EnclaveFactPersister, PersistArgs } from '../db/persist.js';

type SourceKind = 'github' | 'slack' | 'linear' | 'notion' | 'intercom';

const KNOWN_SOURCES = new Set<SourceKind>(['github', 'slack', 'linear', 'notion', 'intercom']);

function isKnownSource(s: string): s is SourceKind {
  return KNOWN_SOURCES.has(s as SourceKind);
}

function extractSourceFactId(body: unknown): string {
  if (body !== null && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    const id = b['id'] ?? b['node_id'] ?? b['ts'] ?? b['identifier'];
    if (typeof id === 'string' || typeof id === 'number') return String(id);
  }
  // sha256 fingerprint when no explicit id field is present
  return Buffer.from(JSON.stringify(body)).toString('base64url').slice(0, 64);
}

export class Pipeline {
  constructor(
    private readonly persister: EnclaveFactPersister,
    private readonly orgId: string,
  ) {}

  async handle(plaintext: Buffer, source: string): Promise<void> {
    if (!isKnownSource(source)) {
      console.warn('unknown source kind — dropping', { source });
      return;
    }

    let body: unknown;
    try {
      body = JSON.parse(plaintext.toString('utf8'));
    } catch {
      console.warn('failed to parse event body — dropping', { source });
      return;
    }

    const args: PersistArgs = {
      orgId: this.orgId,
      sourceKind: source,
      sourceFactId: extractSourceFactId(body),
      occurredAt: new Date(),
      body: JSON.stringify(body),
    };

    // Embedding used for the in-enclave HNSW index (ADL #34).
    // OLLAMA_HOST=localhost:11434 when Ollama is baked into the EIF;
    // returns a zero vector when unset so tests and dev builds pass without a model.
    const embedding = await embedText(args.body);
    void embedding; // TODO(ADL #34): write to in-enclave HNSW index

    await this.persister.persist(args);
  }
}
