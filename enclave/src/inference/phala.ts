import { TeeEndpointBackend } from '@folklore/inference';

const PROXY_PORT = process.env['VSOCK_INFERENCE_PROXY_PORT'] ?? '';
const API_KEY = process.env['TEE_API_KEY'];
const EMBED_MODEL = process.env['EMBED_MODEL'] ?? 'qwen/qwen3-embedding-8b';
const GENERATE_MODEL = process.env['GENERATE_MODEL'] ?? 'deepseek-v4-pro';

let _backend: TeeEndpointBackend | null = null;

function getBackend(): TeeEndpointBackend {
  if (!_backend) {
    _backend = new TeeEndpointBackend({
      baseUrl: PROXY_PORT ? `https://localhost:${PROXY_PORT}` : 'https://api.phala.com/v1',
      apiKey: API_KEY,
      embedModel: EMBED_MODEL,
      generateModel: GENERATE_MODEL,
    });
  }
  return _backend;
}

export async function embedText(text: string): Promise<number[]> {
  if (!PROXY_PORT && !API_KEY) return new Array(768).fill(0) as number[];
  return getBackend().embed(text);
}

export async function generate(prompt: string, systemPrompt?: string): Promise<string> {
  if (!PROXY_PORT && !API_KEY) return '';
  return getBackend().generate(prompt, { systemPrompt });
}
