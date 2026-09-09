import {
  AciReceiptVerifier,
  OpenAICompatBackend,
  TeeEndpointBackend,
  type InferenceResponseVerifier,
  type ToolSpec,
} from '@folklore/inference';
import {
  inferenceTrustPolicyV1Schema,
  inferenceTrustPolicyV2Schema,
  type InferenceModelRole,
  type InferenceTrustPolicyV1,
  type InferenceTrustPolicyV2,
} from '@folklore/contracts';
import { createTelemetryClient, type TelemetryClient } from '@folklore/telemetry';
import {
  inferenceAttestationConfigSchema,
  type InferenceAttestationConfig,
} from '@folklore/contracts/enclave-attestation';
import { CRITIQUE_TEMPERATURE, type SynthesisInference } from './CachedInference.js';
import { recordTokenUsage } from './TokenUsageScope.js';
import { createPinnedInferenceFetch } from '../egress/inference.js';

const PROXY_PORT = process.env['VSOCK_INFERENCE_PROXY_PORT'] ?? '';
const DEFAULT_EMBED_DIM = 4096;
const DEFAULT_GENERATE_MAX_TOKENS = 8192;
export let EMBED_MODEL = '';
export let GENERATE_MODEL = '';
let JUDGE_MODEL = '';
const JUDGE_MAX_TOKENS = Number(process.env['JUDGE_MAX_TOKENS'] ?? '4096');

export let CRITIQUE_MODEL = '';
let MODEL_ALLOWLIST: readonly string[] = [];

const PROVIDER_SEPARATOR = '/';

export const RECEIPT_POLICY = 'per-call' as const;

export interface SyntheticPhalaPayloadV1 {
  payloadKind: 'synthetic-commissioning' | 'customer-content';
  body: Uint8Array;
}

export class SyntheticPhalaInferenceError extends Error {
  readonly code = 'provider_not_synthetic' as const;

  constructor() {
    super('provider_not_synthetic');
    this.name = 'SyntheticPhalaInferenceError';
  }
}

// UNWIRED: synthetic commissioning is test-only and has no live provider caller.
export function assertSyntheticPhalaPayload(input: SyntheticPhalaPayloadV1): void {
  if (process.env['NODE_ENV'] === 'production' || input.payloadKind !== 'synthetic-commissioning') {
    throw new SyntheticPhalaInferenceError();
  }
}

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
      `${role} must be a different provider family than the generate role; both are "${drafter}"`,
    );
  }
}

function assertAllowlisted(role: string, model: string, allowlist: readonly string[]): void {
  if (!allowlist.includes(model)) {
    throw new Error(`${role} "${model}" is not on the verified-model allowlist`);
  }
}

function assertPolicyRoleModels(policy: InferenceTrustPolicyV1): void {
  assertCrossFamily(
    'critique role',
    policy.roleModels.critique.model,
    policy.roleModels.generate.model,
  );
  assertCrossFamily('judge role', policy.roleModels.judge.model, policy.roleModels.generate.model);
}

let GENERATE_MAX_TOKENS = DEFAULT_GENERATE_MAX_TOKENS;
export let EMBED_DIM = DEFAULT_EMBED_DIM;

function apiKey(): string | undefined {
  return process.env['TEE_API_KEY'];
}

type InferenceAttestationInput = Omit<InferenceAttestationConfig, 'modelAllowlist'> & {
  readonly modelAllowlist: readonly string[];
};
type SignedInferenceAttestation = Readonly<InferenceAttestationInput>;

let _backend: TeeEndpointBackend | OpenAICompatBackend | null = null;
let _telemetry: TelemetryClient | null = null;
let _verifiedReceiptSink: ((sessionId: string) => void | Promise<void>) | undefined;
let _inferenceTrustPolicy: InferenceTrustPolicyV1 | undefined;
let _publicInferenceTrustPolicy: InferenceTrustPolicyV2 | undefined;
let _inferenceFetch: typeof fetch | null = null;
let _inferencePolicy: SignedInferenceAttestation | null = null;
let _isLocalPolicy = false;
// Set only from the signature-verified boot manifest's inferenceCommissioning marker. This, not the
// absence of a trust policy, is what authorizes staged (unverified) inference in production.
let _commissioningUnverified = false;
let _commissioningTlsSpki: readonly string[] | undefined;

const TEST_ROLE_MODELS: Record<InferenceModelRole, { model: string; revision: string }> = {
  embed: { model: 'qwen/qwen3-embedding-8b', revision: 'test' },
  generate: { model: 'z-ai/glm-5.2', revision: 'test' },
  judge: { model: 'qwen/qwen3-32b', revision: 'test' },
  critique: { model: 'qwen/qwen3-32b', revision: 'test' },
};

export function inferenceModel(role: InferenceModelRole): string {
  return inferenceRoleModel(role).model;
}

export function inferenceModelRevision(role: InferenceModelRole): string {
  return inferenceRoleModel(role).revision;
}

export function setInferenceTelemetry(client: TelemetryClient): void {
  _telemetry = client;
}

export function setVerifiedInferenceReceiptSink(
  sink: (sessionId: string) => void | Promise<void>,
): void {
  _verifiedReceiptSink = sink;
}

export function setInferenceTrustPolicy(policy: unknown): void {
  if (policy === undefined) {
    _inferenceTrustPolicy = undefined;
    _backend = null;
    _inferenceFetch = null;
    return;
  }
  const parsed = inferenceTrustPolicyV1Schema.parse(policy);
  if (_publicInferenceTrustPolicy) {
    throw new Error('signed inference trust policy conflicts with public inference trust policy');
  }
  if (_inferenceTrustPolicy) {
    if (JSON.stringify(_inferenceTrustPolicy) !== JSON.stringify(parsed)) {
      throw new Error('signed inference trust policy changed');
    }
    return;
  }
  _inferenceTrustPolicy = parsed;
  if (_inferenceTrustPolicy) assertPolicyRoleModels(_inferenceTrustPolicy);
  _backend = null;
  _inferenceFetch = null;
}

/** Configure the public provider profile used only for approved role metadata lookup. */
export function setPublicInferenceTrustPolicy(policy: unknown): void {
  const parsed = inferenceTrustPolicyV2Schema.parse(policy);
  if (parsed.evidence.profile !== 'dstack-tdx-public-v1') {
    throw new Error('public inference trust policy requires dstack-tdx-public-v1 profile');
  }
  if (_inferenceTrustPolicy || _inferencePolicy || _isLocalPolicy || _commissioningUnverified) {
    throw new Error('public inference trust policy conflicts with legacy inference policy');
  }
  if (_publicInferenceTrustPolicy) {
    if (JSON.stringify(_publicInferenceTrustPolicy) !== JSON.stringify(parsed)) {
      throw new Error('public inference trust policy changed');
    }
    return;
  }
  _publicInferenceTrustPolicy = parsed;
  _backend = null;
  _inferenceFetch = null;
}

// Enable staged (unverified) inference from the signature-verified boot manifest's commissioning
// marker. Production-safe because the manifest is signed and PCR-gated; refuses to run staged unless
// the marker is present. Forbidden alongside a full trust policy (that must keep the real verifier).
export function setInferenceCommissioning(
  marker: { unverifiedReceipts: true; tlsSpkiSha256: readonly string[] } | undefined,
): void {
  if (marker === undefined) {
    _commissioningUnverified = false;
    _commissioningTlsSpki = undefined;
    return;
  }
  if (_inferenceTrustPolicy) {
    throw new Error('inference commissioning marker conflicts with a signed trust policy');
  }
  if (_publicInferenceTrustPolicy) {
    throw new Error('inference commissioning marker conflicts with public inference trust policy');
  }
  _commissioningUnverified = true;
  _commissioningTlsSpki = marker.tlsSpkiSha256;
}

export function configureInferenceAttestation(input: InferenceAttestationInput): void {
  if (_publicInferenceTrustPolicy) {
    throw new Error('signed inference attestation conflicts with public inference trust policy');
  }
  const parsed = inferenceAttestationConfigSchema.parse(input);
  if (_inferencePolicy) {
    if (!sameInferenceAttestation(_inferencePolicy, parsed)) {
      throw new Error('signed inference attestation changed');
    }
    return;
  }
  assertCrossFamily('CRITIQUE_MODEL', parsed.critiqueModel, parsed.generateModel);
  assertAllowlisted('CRITIQUE_MODEL', parsed.critiqueModel, parsed.modelAllowlist);
  assertCrossFamily('JUDGE_MODEL', parsed.judgeModel, parsed.generateModel);
  assertAllowlisted('JUDGE_MODEL', parsed.judgeModel, parsed.modelAllowlist);
  installInferencePolicy(parsed, false);
}

export function configureLocalInferencePolicy(env: NodeJS.ProcessEnv = process.env): void {
  if (_publicInferenceTrustPolicy) {
    throw new Error('local inference policy conflicts with public inference trust policy');
  }
  if (env['NODE_ENV'] !== 'development' && env['NODE_ENV'] !== 'test') {
    throw new Error('local inference policy forbidden in production');
  }
  if (_inferencePolicy) return;
  const { endpoint, expectedHost } = localEndpoint(env);
  const embedModel = env['EMBED_MODEL']?.trim() || 'nomic-embed-text';
  const generateModel = env['GENERATE_MODEL']?.trim() || 'llama3.1:8b';
  const critiqueModel = env['CRITIQUE_MODEL']?.trim() || generateModel;
  const judgeModel = env['JUDGE_MODEL']?.trim() || generateModel;
  const models = [embedModel, generateModel, critiqueModel, judgeModel];
  const modelAllowlist = localModelAllowlist(env, models);
  for (const model of models) {
    if (!modelAllowlist.includes(model)) {
      throw new Error(`local inference model "${model}" is not allowlisted`);
    }
  }
  installInferencePolicy(
    {
      endpoint,
      expectedHost,
      workloadId: 'local-development',
      keysetDigest: `sha256:${'0'.repeat(64)}`,
      embedModel,
      generateModel,
      critiqueModel,
      judgeModel,
      embedDim: localPositiveInteger(env['EMBED_DIM'], DEFAULT_EMBED_DIM, 'embed dimension'),
      generateMaxTokens: localPositiveInteger(
        env['GENERATE_MAX_TOKENS'],
        DEFAULT_GENERATE_MAX_TOKENS,
        'generation token limit',
      ),
      modelAllowlist,
    },
    true,
  );
}

export function configureInferenceAttestationForTest(input: InferenceAttestationInput): void {
  if (process.env['NODE_ENV'] !== 'development' && process.env['NODE_ENV'] !== 'test') {
    throw new Error('test inference attestation forbidden in production');
  }
  configureInferenceAttestation(input);
}

export function assertInferenceAttestationEcho(input: InferenceAttestationInput | undefined): void {
  if (input === undefined) return;
  const parsed = inferenceAttestationConfigSchema.parse(input);
  if (!sameInferenceAttestation(signedInferenceAttestation(), parsed)) {
    throw new Error('assignment inference policy disagrees with signed boot manifest');
  }
}

function sameInferenceAttestation(
  current: SignedInferenceAttestation,
  candidate: InferenceAttestationInput,
): boolean {
  return JSON.stringify(current) === JSON.stringify(candidate);
}

function signedInferenceAttestation(): SignedInferenceAttestation {
  if (_inferencePolicy) return _inferencePolicy;
  throw new Error('signed inference attestation unavailable');
}

function localEndpoint(env: NodeJS.ProcessEnv): { endpoint: string; expectedHost: string } {
  const endpoint = env['TEE_ENDPOINT_URL']?.trim() || 'http://localhost:11434/v1';
  const url = new URL(endpoint);
  const isLoopbackHttp =
    url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !isLoopbackHttp) {
    throw new Error('local inference endpoint must use HTTPS or HTTP loopback');
  }
  return { endpoint, expectedHost: url.hostname };
}

function localModelAllowlist(env: NodeJS.ProcessEnv, models: readonly string[]): string[] {
  const configured = env['INFERENCE_MODEL_ALLOWLIST']
    ?.split(',')
    .map((model) => model.trim())
    .filter((model) => model.length > 0);
  return configured?.length ? configured : [...new Set(models)];
}

function localPositiveInteger(raw: string | undefined, fallback: number, name: string): number {
  const value = Number(raw ?? fallback);
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`local ${name} invalid`);
  return value;
}

function installInferencePolicy(input: InferenceAttestationInput, isLocal: boolean): void {
  const policy = Object.freeze({
    ...input,
    modelAllowlist: Object.freeze([...input.modelAllowlist]),
  });
  _inferencePolicy = policy;
  _isLocalPolicy = isLocal;
  EMBED_MODEL = policy.embedModel;
  GENERATE_MODEL = policy.generateModel;
  CRITIQUE_MODEL = policy.critiqueModel;
  JUDGE_MODEL = policy.judgeModel;
  EMBED_DIM = policy.embedDim;
  GENERATE_MAX_TOKENS = policy.generateMaxTokens;
  MODEL_ALLOWLIST = policy.modelAllowlist;
}

function telemetry(): TelemetryClient {
  return (_telemetry ??= createTelemetryClient());
}

let _stagedVerificationWarned = false;

// Loud, content-free, once-per-boot: records that inference receipt verification is staged OFF for a
// commissioning tenant so the outage is observable rather than silent. Never reached in production
// unless INFERENCE_COMMISSIONING_UNVERIFIED=1 was set explicitly (see allowsUnverifiedInference).
function warnStagedInferenceVerification(): void {
  if (_stagedVerificationWarned) return;
  _stagedVerificationWarned = true;
  const mode = process.env['NODE_ENV'] === 'production' ? 'commissioning' : 'non_production';
  process.stderr.write(
    `inference.receipt_verification.staged_off mode=${mode} — pinned endpoint, receipts NOT verified\n`,
  );
  // Relayed to the control plane via the check-in ops-event channel, so the staged-off state is
  // observable where the enclave's own stderr is not (production has no debug-mode log reader).
  telemetry().track('inference.receipt_verification_staged_off', 'system', { mode });
}

export function buildReceiptVerifier(
  telemetryClient: TelemetryClient = telemetry(),
  fetchImpl?: typeof fetch,
): InferenceResponseVerifier {
  if (_inferenceTrustPolicy) {
    const trustPolicy = _inferenceTrustPolicy;
    const transport = fetchImpl ?? pinnedInferenceFetch(trustPolicy);
    return new AciReceiptVerifier({
      baseUrl: resolveBaseUrl(),
      trustPolicy,
      apiKey: apiKey(),
      policy: RECEIPT_POLICY,
      telemetry: telemetryClient,
      verifiedReceiptSink: _verifiedReceiptSink,
      fetchImpl: transport,
    });
  }
  if (isTestOnlyUnverifiedInference() && !_inferencePolicy) {
    return {
      ensureAttested: async () => undefined,
      verifyReceipt: async () => undefined,
    };
  }
  if (_inferencePolicy && allowsUnverifiedInference()) {
    warnStagedInferenceVerification();
    return {
      ensureAttested: async () => undefined,
      verifyReceipt: async () => undefined,
    };
  }
  throw new Error('inference commissioning prerequisite unmet: signed trust policy unavailable');
}

function getBackend(): TeeEndpointBackend | OpenAICompatBackend {
  if (_publicInferenceTrustPolicy) {
    throw new Error('global inference backend unavailable under public inference profile');
  }
  if (_backend) return _backend;

  if (_isLocalPolicy) {
    _backend = new OpenAICompatBackend({
      baseUrl: resolveBaseUrl(),
      apiKey: apiKey(),
      embedModel: EMBED_MODEL,
      generateModel: GENERATE_MODEL,
      modelAllowlist: MODEL_ALLOWLIST,
      usageSink: recordTokenUsage,
      telemetry: telemetry(),
    });
    return _backend;
  }

  if (_inferenceTrustPolicy) {
    const trustPolicy = currentInferenceTrustPolicy();
    const fetchImpl = pinnedInferenceFetch(trustPolicy);
    _backend = new TeeEndpointBackend({
      baseUrl: resolveBaseUrl(),
      apiKey: apiKey(),
      trustPolicy,
      responseVerifier: buildReceiptVerifier(undefined, fetchImpl),
      usageSink: recordTokenUsage,
      telemetry: telemetry(),
      fetchImpl,
    });
    return _backend;
  }

  if (!_inferencePolicy || !allowsUnverifiedInference()) {
    throw new Error('inference commissioning prerequisite unmet: signed trust policy unavailable');
  }

  _backend = new OpenAICompatBackend({
    baseUrl: resolveBaseUrl(),
    apiKey: apiKey(),
    embedModel: EMBED_MODEL,
    generateModel: GENERATE_MODEL,
    modelAllowlist: MODEL_ALLOWLIST,
    responseVerifier: buildReceiptVerifier(),
    usageSink: recordTokenUsage,
    telemetry: telemetry(),
    // Even with receipt verification staged off, keep the TLS transport pinned to the real endpoint
    // SPKI (from the signed commissioning marker) so content never egresses to an unpinned host.
    ...(commissioningPinnedFetch() ? { fetchImpl: commissioningPinnedFetch()! } : {}),
  });
  return _backend;
}

// A pinned fetch for staged commissioning inference: same transport pinning as the verified path
// (proxy + SPKI), built from the pins endpoint and the signed marker's tlsSpkiSha256.
function commissioningPinnedFetch(): typeof fetch | undefined {
  if (!_commissioningUnverified || !_commissioningTlsSpki || !_inferencePolicy) return undefined;
  const url = new URL(_inferencePolicy.endpoint);
  return (_inferenceFetch ??= createPinnedInferenceFetch({
    origin: url.origin,
    route: url.pathname,
    tlsSpkiSha256: [..._commissioningTlsSpki],
  }));
}

function pinnedInferenceFetch(policy: InferenceTrustPolicyV1): typeof fetch {
  return (_inferenceFetch ??= createPinnedInferenceFetch(policy));
}

export function resolveBaseUrl(): string {
  if (_publicInferenceTrustPolicy) {
    return `${_publicInferenceTrustPolicy.origin}${_publicInferenceTrustPolicy.route}`;
  }
  if (_inferenceTrustPolicy) {
    return `${_inferenceTrustPolicy.origin}${_inferenceTrustPolicy.route}`;
  }
  if (_inferencePolicy) return _inferencePolicy.endpoint;
  if (isTestOnlyUnverifiedInference()) return testEndpoint();
  throw new Error('signed inference attestation unavailable');
}

export function assertInferenceConfigured(): void {
  if (_publicInferenceTrustPolicy) {
    if (!apiKey()) {
      throw new Error('inference not configured: set TEE_API_KEY');
    }
    resolveBaseUrl();
    return;
  }
  if (_isLocalPolicy) {
    resolveBaseUrl();
    return;
  }

  if (!_inferenceTrustPolicy && !(_inferencePolicy && allowsUnverifiedInference())) {
    currentInferenceTrustPolicy();
  }
  if (!PROXY_PORT && !apiKey()) {
    throw new Error('inference not configured: set VSOCK_INFERENCE_PROXY_PORT or TEE_API_KEY');
  }
  resolveBaseUrl();
  if (_inferenceTrustPolicy) currentInferenceTrustPolicy();
}

function currentInferenceTrustPolicy(): InferenceTrustPolicyV1 {
  if (_inferenceTrustPolicy) return _inferenceTrustPolicy;
  if (isTestOnlyUnverifiedInference()) return testOnlyTrustPolicy();
  return requireInferenceTrustPolicy();
}

function requireInferenceTrustPolicy(): InferenceTrustPolicyV1 {
  if (!_inferenceTrustPolicy) {
    throw new Error('inference commissioning prerequisite unmet: signed trust policy unavailable');
  }
  return _inferenceTrustPolicy;
}

function inferenceRoleModel(role: InferenceModelRole): { model: string; revision: string } {
  if (_publicInferenceTrustPolicy) return _publicInferenceTrustPolicy.roleModels[role];
  if (_inferenceTrustPolicy) return _inferenceTrustPolicy.roleModels[role];
  if (_inferencePolicy) return { model: roleModelName(role), revision: 'unversioned' };
  if (process.env['NODE_ENV'] === 'test') return TEST_ROLE_MODELS[role];
  return requireInferenceTrustPolicy().roleModels[role];
}

function roleModelName(role: InferenceModelRole): string {
  if (!_inferencePolicy) throw new Error('signed inference attestation unavailable');
  return {
    embed: _inferencePolicy.embedModel,
    generate: _inferencePolicy.generateModel,
    judge: _inferencePolicy.judgeModel,
    critique: _inferencePolicy.critiqueModel,
  }[role];
}

function isNonProductionEnvironment(): boolean {
  return process.env['NODE_ENV'] !== 'production';
}

// Staged (unverified) inference is permitted only when: this is a non-production env, OR the
// signature-verified boot manifest carried the explicit inferenceCommissioning marker
// (_commissioningUnverified). It is NEVER inferred from the absence of a trust policy — the
// active-policy carrier path also has no trust policy, and must keep the real verifier.
function allowsUnverifiedInference(): boolean {
  return isNonProductionEnvironment() || _commissioningUnverified;
}

function isTestOnlyUnverifiedInference(): boolean {
  return (
    process.env['NODE_ENV'] === 'test' && process.env['INFERENCE_TEST_ALLOW_UNVERIFIED'] === '1'
  );
}

function testEndpoint(): string {
  const configured = process.env['TEE_ENDPOINT_URL']?.trim();
  if (configured) return configured;
  if (PROXY_PORT) return `https://localhost:${PROXY_PORT}`;
  return 'https://localhost';
}

function testOnlyTrustPolicy(): InferenceTrustPolicyV1 {
  const endpoint = new URL(testEndpoint());
  const roleModels = TEST_ROLE_MODELS;
  return inferenceTrustPolicyV1Schema.parse({
    version: 1,
    generation: 1,
    origin: endpoint.origin,
    route: endpoint.pathname || '/',
    redirectOrigins: [],
    tlsSpkiSha256: ['0'.repeat(64)],
    workloadId: 'test-workload',
    quoteRootDigests: ['0'.repeat(64)],
    workloadMeasurements: ['0'.repeat(96)],
    attestationKeys: [
      { keyId: 'test-attestation', algorithm: 'Ed25519', publicKey: `${'A'.repeat(43)}=` },
    ],
    receiptKeys: [{ keyId: 'test-receipt', algorithm: 'Ed25519', publicKey: `${'B'.repeat(43)}=` }],
    permittedModels: [
      ...new Map(
        Object.values(TEST_ROLE_MODELS).map((model) => [`${model.model} ${model.revision}`, model]),
      ).values(),
    ].sort((left, right) => {
      const leftKey = `${left.model} ${left.revision}`;
      const rightKey = `${right.model} ${right.revision}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    }),
    roleModels,
  });
}

export async function embedText(text: string): Promise<number[]> {
  assertInferenceConfigured();
  const vector = await getBackend().embed(text);
  if (vector.length !== EMBED_DIM) {
    throw new Error(`embedding dimension mismatch: expected ${EMBED_DIM}, got ${vector.length}`);
  }
  return vector;
}

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
    modelRole: 'critique',
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
    modelRole: 'judge',
    maxTokens: JUDGE_MAX_TOKENS,
    temperature: 0,
  });
}

export const phalaInference: SynthesisInference = {
  embed: (text) => embedText(text),
  generate: (prompt, systemPrompt, temperature) => generate(prompt, systemPrompt, temperature),
  critique: (prompt, systemPrompt) => generateCritique(prompt, systemPrompt),
};
