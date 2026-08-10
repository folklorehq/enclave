import {
  AciReceiptVerifier,
  parseModelAllowlist,
  TeeEndpointBackend,
  type InferenceResponseVerifier,
  type ReceiptVerificationPolicy,
  type ToolSpec,
} from '@folklore/inference';
import { createTelemetryClient, type TelemetryClient } from '@folklore/telemetry';
import { CRITIQUE_TEMPERATURE, type SynthesisInference } from './CachedInference.js';
import { recordTokenUsage } from './TokenUsageScope.js';

const PROXY_PORT = process.env['VSOCK_INFERENCE_PROXY_PORT'] ?? '';
export const EMBED_MODEL = process.env['EMBED_MODEL'] ?? 'qwen/qwen3-embedding-8b';
export const GENERATE_MODEL = process.env['GENERATE_MODEL'] ?? 'z-ai/glm-5.2';
// The relevance/citation judge — a smaller allowlisted model, off the drafter's family (enforced below).
const JUDGE_MODEL = process.env['JUDGE_MODEL'] ?? 'qwen/qwen3-32b';
const JUDGE_MAX_TOKENS = Number(process.env['JUDGE_MAX_TOKENS'] ?? '4096');

// A model reviewing its own draft is blind to its own defects, and that blindness barely transfers
// across providers, so this may never resolve to GENERATE_MODEL's provider (enforced below).
export const CRITIQUE_MODEL = process.env['CRITIQUE_MODEL'] ?? 'qwen/qwen3-32b';

// Fail-closed guard: only these live-verified TEE-confidential models may receive decrypted
// content. inference.phala.com serves unverified models on the same endpoint.
const MODEL_ALLOWLIST = parseModelAllowlist(process.env['INFERENCE_MODEL_ALLOWLIST']);

const PROVIDER_SEPARATOR = '/';

// Normalized before comparing: "Z-AI/glm-4" and "z-ai/glm-5.2" are one family, not two.
export function familyOf(model: string): string {
  const normalized = model.trim().toLowerCase();
  const separator = normalized.indexOf(PROVIDER_SEPARATOR);
  const family = separator > 0 ? normalized.slice(0, separator).trim() : '';
  if (!family) throw new Error(`model name missing provider prefix: ${model}`);
  return family;
}

export function assertCrossFamily(role: string, model: string, generateModel: string): void {
  const drafter = familyOf(generateModel);
  if (drafter === familyOf(model)) {
    throw new Error(
      `${role} must be a different provider family than GENERATE_MODEL; both are "${drafter}"`,
    );
  }
}

function assertAllowlisted(role: string, model: string): void {
  if (!MODEL_ALLOWLIST.includes(model)) {
    throw new Error(`${role} "${model}" is not on the verified-model allowlist`);
  }
}

// At module init, not at first call: a misrouted judge must stop the boot, not surface as a
// silently unreviewed page mid-synthesis.
assertCrossFamily('CRITIQUE_MODEL', CRITIQUE_MODEL, GENERATE_MODEL);
assertAllowlisted('CRITIQUE_MODEL', CRITIQUE_MODEL);
assertCrossFamily('JUDGE_MODEL', JUDGE_MODEL, GENERATE_MODEL);
assertAllowlisted('JUDGE_MODEL', JUDGE_MODEL);

// ACI receipt verification (attestation pin + per-response upstream.verified) is POLICY, not
// configuration: TEE_ENDPOINT_URL comes from the parent, so a flag the parent could omit was an
// off-switch for the only check that inference runs in a TEE at all. Only a dev run may opt out,
// and entrypoint.sh pins NODE_ENV=production so the parent cannot claim to be one. This closes the
// omitted-flag path and not the redirect itself: aci-verifier fetches the pin from that same
// parent-chosen endpoint (audit F1), so a redirected host can still serve a pin it made up.
const DEV_OR_TEST = process.env['NODE_ENV'] === 'development' || process.env['NODE_ENV'] === 'test';
const VERIFY_RECEIPTS = DEV_OR_TEST ? process.env['INFERENCE_ACI_VERIFY'] === '1' : true;
// Strengthening-only: absent means off, so a parent can turn this ON but never off.
const ENFORCE_RECEIPT_SIGNATURE = process.env['INFERENCE_ACI_ENFORCE_SIGNATURE'] === '1';

// Enclave synthesis is async (not user-latency-critical), so verify every receipt — this catches a
// gateway that reroutes a mid-session call to an unverified upstream. Constant, not configurable:
// the only other value is weaker, and every env knob here is one the parent writes.
export const RECEIPT_POLICY: ReceiptVerificationPolicy = 'per-call';

// z-ai/glm-5.2 is a reasoning model: reasoning tokens count against max_tokens, so a
// tight cap returns empty content (the budget is spent thinking). Keep it generous for
// long-form synthesis; configurable per deployment.
const GENERATE_MAX_TOKENS = Number(process.env['GENERATE_MAX_TOKENS'] ?? '8192');

// A bad override must fail loudly at boot rather than silently poison every dimension-derived size.
function readEmbedDim(): number {
  const parsed = Number(process.env['EMBED_DIM'] || '4096');
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(
      `EMBED_DIM must be a positive integer, got ${JSON.stringify(process.env['EMBED_DIM'])}`,
    );
  }
  return parsed;
}

// qwen/qwen3-embedding-8b returns 4096-dim vectors natively and rejects the OpenAI
// `dimensions` truncation param, so we never request a dimension — we validate the
// native length. EMBED_DIM sizes the HNSW index, the offline fallback, and this guard.
export const EMBED_DIM = readEmbedDim();

// The key is read lazily (not at module load) because boot fetches it from SSM into
// the environment before the first inference call — see loadInferenceKey in index.ts.
function apiKey(): string | undefined {
  return process.env['TEE_API_KEY'];
}

// no hardcoded provider host as a functional default — a dead default URL
// soft-fails to empty wikis. TEE_ENDPOINT_URL wins; in-enclave the vsock proxy
// port is the fallback.
export function resolveBaseUrl(): string {
  const url = process.env['TEE_ENDPOINT_URL'];
  if (url) return url;
  if (PROXY_PORT) return `https://localhost:${PROXY_PORT}`;
  throw new Error(
    'inference endpoint not configured: set TEE_ENDPOINT_URL or VSOCK_INFERENCE_PROXY_PORT',
  );
}

let _backend: TeeEndpointBackend | null = null;
let _telemetry: TelemetryClient | null = null;

// In-enclave there is no PostHog egress, so boot injects a sink that buffers ops events
// onto the check-in. Absent an injection (dev/local) this falls back to the
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
      usageSink: recordTokenUsage,
      telemetry: telemetry(),
    });
  }
  return _backend;
}

// a missing endpoint/key must fail loudly — a silent zero-vector / empty-string
// fallback would poison the HNSW index and persist empty wikis as if synthesis worked.
export function assertInferenceConfigured(): void {
  // Credentials only — the endpoint is resolveBaseUrl's to reject, and after A4 Lane D the knob it
  // names is TEE_ENDPOINT_URL, which neither variable below would fix.
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

export async function generateCritique(prompt: string, systemPrompt?: string): Promise<string> {
  assertInferenceConfigured();
  return getBackend().generate(prompt, {
    systemPrompt,
    model: CRITIQUE_MODEL,
    maxTokens: JUDGE_MAX_TOKENS,
    temperature: CRITIQUE_TEMPERATURE,
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
export const phalaInference: SynthesisInference = {
  embed: (text) => embedText(text),
  generate: (prompt, systemPrompt, temperature) => generate(prompt, systemPrompt, temperature),
  critique: (prompt, systemPrompt) => generateCritique(prompt, systemPrompt),
};
