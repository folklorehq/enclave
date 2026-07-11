import { TeeEndpointBackend } from '@folklore/inference';

const PROXY_PORT = process.env['VSOCK_INFERENCE_PROXY_PORT'] ?? '';
const EMBED_MODEL = process.env['EMBED_MODEL'] ?? 'qwen/qwen3-embedding-8b';
const GENERATE_MODEL = process.env['GENERATE_MODEL'] ?? 'deepseek-v4-pro';

// One dimension sizes the HNSW index, the offline fallback, and the requested
// `dimensions` param, so all three agree. Override to the model's native dimension
// (4096) if the endpoint ignores matryoshka truncation.
export const EMBED_DIM = Number(process.env['EMBED_DIM'] ?? '768');

// The key is read lazily (not at module load) because boot fetches it from SSM into
// the environment before the first inference call — see loadInferenceKey in index.ts.
function apiKey(): string | undefined {
  return process.env['TEE_API_KEY'];
}

let _backend: TeeEndpointBackend | null = null;

function getBackend(): TeeEndpointBackend {
  if (!_backend) {
    _backend = new TeeEndpointBackend({
      baseUrl: PROXY_PORT ? `https://localhost:${PROXY_PORT}` : 'https://api.phala.com/v1',
      apiKey: apiKey(),
      embedModel: EMBED_MODEL,
      embedDimensions: EMBED_DIM,
      generateModel: GENERATE_MODEL,
    });
  }
  return _backend;
}

// ADL #40: a missing endpoint must fail loudly — a silent zero-vector / empty-string
// fallback would poison the HNSW index and persist empty wikis as if synthesis worked.
export function assertInferenceConfigured(): void {
  if (!PROXY_PORT && !apiKey()) {
    throw new Error('inference not configured: set VSOCK_INFERENCE_PROXY_PORT or TEE_API_KEY');
  }
}

export async function embedText(text: string): Promise<number[]> {
  assertInferenceConfigured();
  const vector = await getBackend().embed(text);
  if (vector.length !== EMBED_DIM) {
    throw new Error(`embedding dimension mismatch: expected ${EMBED_DIM}, got ${vector.length}`);
  }
  return vector;
}

export async function generate(prompt: string, systemPrompt?: string): Promise<string> {
  assertInferenceConfigured();
  return getBackend().generate(prompt, { systemPrompt });
}
