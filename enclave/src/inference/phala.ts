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

export async function embedText(text: string): Promise<number[]> {
  if (!PROXY_PORT && !apiKey()) return new Array(EMBED_DIM).fill(0) as number[];
  const vector = await getBackend().embed(text);
  if (vector.length !== EMBED_DIM) {
    throw new Error(`embedding dimension mismatch: expected ${EMBED_DIM}, got ${vector.length}`);
  }
  return vector;
}

export async function generate(prompt: string, systemPrompt?: string): Promise<string> {
  if (!PROXY_PORT && !apiKey()) return '';
  return getBackend().generate(prompt, { systemPrompt });
}
