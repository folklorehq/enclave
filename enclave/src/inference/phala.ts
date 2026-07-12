import {
  AciReceiptVerifier,
  parseModelAllowlist,
  TeeEndpointBackend,
  type InferenceResponseVerifier,
} from '@folklore/inference';

const PROXY_PORT = process.env['VSOCK_INFERENCE_PROXY_PORT'] ?? '';
const EMBED_MODEL = process.env['EMBED_MODEL'] ?? 'qwen/qwen3-embedding-8b';
const GENERATE_MODEL = process.env['GENERATE_MODEL'] ?? 'z-ai/glm-5.2';

// Fail-closed guard: only these live-verified TEE-confidential models may receive decrypted
// content (ADL #30/#40). inference.phala.com serves unverified models on the same endpoint.
const MODEL_ALLOWLIST = parseModelAllowlist(process.env['INFERENCE_MODEL_ALLOWLIST']);

// ACI receipt verification (attestation pin + per-response upstream.verified). Enabled via
// infra; signature enforcement stays a separate opt-in until reconciled with live receipts.
const VERIFY_RECEIPTS = process.env['INFERENCE_ACI_VERIFY'] === '1';
const ENFORCE_RECEIPT_SIGNATURE = process.env['INFERENCE_ACI_ENFORCE_SIGNATURE'] === '1';

// z-ai/glm-5.2 is a reasoning model: reasoning tokens count against max_tokens, so a
// tight cap returns empty content (the budget is spent thinking). Keep it generous for
// long-form synthesis; configurable per deployment.
const GENERATE_MAX_TOKENS = Number(process.env['GENERATE_MAX_TOKENS'] ?? '8192');

// qwen/qwen3-embedding-8b returns 4096-dim vectors natively and rejects the OpenAI
// `dimensions` truncation param, so we never request a dimension — we validate the
// native length. EMBED_DIM sizes the HNSW index, the offline fallback, and this guard.
export const EMBED_DIM = Number(process.env['EMBED_DIM'] ?? '4096');

// The key is read lazily (not at module load) because boot fetches it from SSM into
// the environment before the first inference call — see loadInferenceKey in index.ts.
function apiKey(): string | undefined {
  return process.env['TEE_API_KEY'];
}

// ADL #40: no hardcoded provider host as a functional default — a dead default URL
// soft-fails to empty wikis. In-enclave the vsock proxy port wins; otherwise
// TEE_ENDPOINT_URL is required.
function resolveBaseUrl(): string {
  if (PROXY_PORT) return `https://localhost:${PROXY_PORT}`;
  const url = process.env['TEE_ENDPOINT_URL'];
  if (!url) {
    throw new Error(
      'inference endpoint not configured: set TEE_ENDPOINT_URL or VSOCK_INFERENCE_PROXY_PORT',
    );
  }
  return url;
}

let _backend: TeeEndpointBackend | null = null;

function buildReceiptVerifier(): InferenceResponseVerifier | undefined {
  if (!VERIFY_RECEIPTS) return undefined;
  return new AciReceiptVerifier({
    baseUrl: resolveBaseUrl(),
    apiKey: apiKey(),
    enforceReceiptSignature: ENFORCE_RECEIPT_SIGNATURE,
  });
}

function getBackend(): TeeEndpointBackend {
  if (!_backend) {
    _backend = new TeeEndpointBackend({
      baseUrl: resolveBaseUrl(),
      apiKey: apiKey(),
      embedModel: EMBED_MODEL,
      generateModel: GENERATE_MODEL,
      modelAllowlist: MODEL_ALLOWLIST,
      responseVerifier: buildReceiptVerifier(),
    });
  }
  return _backend;
}

// ADL #40: a missing endpoint/key must fail loudly — a silent zero-vector / empty-string
// fallback would poison the HNSW index and persist empty wikis as if synthesis worked.
export function assertInferenceConfigured(): void {
  if (!PROXY_PORT && !apiKey()) {
    throw new Error('inference not configured: set VSOCK_INFERENCE_PROXY_PORT or TEE_API_KEY');
  }
  resolveBaseUrl();
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
  return getBackend().generate(prompt, { systemPrompt, maxTokens: GENERATE_MAX_TOKENS });
}
