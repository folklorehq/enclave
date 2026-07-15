import {
  AciReceiptVerifier,
  parseModelAllowlist,
  TeeEndpointBackend,
  type InferenceResponseVerifier,
  type ReceiptVerificationPolicy,
  type ToolSpec,
} from '@folklore/inference';
import { createTelemetryClient, type TelemetryClient } from '@folklore/telemetry';
import type { InferenceModel } from './cached-inference.js';

const PROXY_PORT = process.env['VSOCK_INFERENCE_PROXY_PORT'] ?? '';
export const EMBED_MODEL = process.env['EMBED_MODEL'] ?? 'qwen/qwen3-embedding-8b';
export const GENERATE_MODEL = process.env['GENERATE_MODEL'] ?? 'z-ai/glm-5.2';
// The relevance/citation judge — a smaller allowlisted TEE-verified model; decrypted content
// still goes only to a verified upstream (ADL #30/#40). Low temperature: this is classification.
const JUDGE_MODEL = process.env['JUDGE_MODEL'] ?? 'qwen/qwen3-32b';
const JUDGE_MAX_TOKENS = Number(process.env['JUDGE_MAX_TOKENS'] ?? '4096');

// Fail-closed guard: only these live-verified TEE-confidential models may receive decrypted
// content (ADL #30/#40). inference.phala.com serves unverified models on the same endpoint.
const MODEL_ALLOWLIST = parseModelAllowlist(process.env['INFERENCE_MODEL_ALLOWLIST']);

// ACI receipt verification (attestation pin + per-response upstream.verified). Enabled via
// infra; signature enforcement stays a separate opt-in until reconciled with live receipts.
const VERIFY_RECEIPTS = process.env['INFERENCE_ACI_VERIFY'] === '1';
const ENFORCE_RECEIPT_SIGNATURE = process.env['INFERENCE_ACI_ENFORCE_SIGNATURE'] === '1';

// Enclave synthesis is async (not user-latency-critical), so verify every receipt — this
// catches a gateway that reroutes a mid-session call to an unverified upstream (ADL #30/#40).
export const RECEIPT_POLICY: ReceiptVerificationPolicy =
  process.env['INFERENCE_ACI_POLICY'] === 'first-call' ? 'first-call' : 'per-call';

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
let _telemetry: TelemetryClient | null = null;

// In-enclave there is no PostHog egress, so boot injects a sink that buffers ops events
// onto the check-in (ADL #18). Absent an injection (dev/local) this falls back to the
// env-resolved client, which is a Noop without POSTHOG_API_KEY.
export function setInferenceTelemetry(client: TelemetryClient): void {
  _telemetry = client;
}

function telemetry(): TelemetryClient {
  return (_telemetry ??= createTelemetryClient());
}

export function buildReceiptVerifier(
  telemetryClient: TelemetryClient = telemetry(),
): InferenceResponseVerifier | undefined {
  if (!VERIFY_RECEIPTS) return undefined;
  return new AciReceiptVerifier({
    baseUrl: resolveBaseUrl(),
    apiKey: apiKey(),
    policy: RECEIPT_POLICY,
    enforceReceiptSignature: ENFORCE_RECEIPT_SIGNATURE,
    telemetry: telemetryClient,
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
      telemetry: telemetry(),
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

// Default temperature 0 (greedy) so classification/judge/labeling/synthesis is deterministic unless
// a caller overrides (determinism #2). Honest ceiling: temp 0 removes sampling variance but a
// TEE-batched LLM still isn't bit-identical run-to-run — the LLM cache is what makes replay exact.
export async function generate(
  prompt: string,
  systemPrompt?: string,
  temperature = 0,
): Promise<string> {
  assertInferenceConfigured();
  return getBackend().generate(prompt, {
    systemPrompt,
    maxTokens: GENERATE_MAX_TOKENS,
    temperature,
  });
}

export async function generateStructured(
  prompt: string,
  tool: ToolSpec,
  systemPrompt?: string,
): Promise<unknown> {
  assertInferenceConfigured();
  const backend = getBackend();
  if (!backend.generateStructured) {
    throw new Error('inference backend does not support tool calling');
  }
  return backend.generateStructured(prompt, {
    tool,
    systemPrompt,
    model: JUDGE_MODEL,
    maxTokens: JUDGE_MAX_TOKENS,
    temperature: 0,
  });
}

// The uncached phala-backed model; the CachedInference layer wraps this per-org where a keyring + S3
// exist (Pipeline, synthesis workers). Arrow wrappers so a partial test mock of this module is safe.
export const phalaInference: InferenceModel = {
  embed: (text) => embedText(text),
  generate: (prompt, systemPrompt, temperature) => generate(prompt, systemPrompt, temperature),
};
