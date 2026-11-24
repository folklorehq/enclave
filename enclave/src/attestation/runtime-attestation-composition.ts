import type { Logger } from '@folklore/core';
import type { S3Client } from '@aws-sdk/client-s3';
import {
  bootManifestSchema,
  controlPlaneIdentitySchema,
  parseBootManifestWire,
  signedBootManifestKeysetSchema,
  signedBootManifestSchema,
  type BootManifest,
  type SignedBootManifestKeyset,
} from '@folklore/contracts/enclave-attestation';
import { ConfigurationError } from '@folklore/errors';
import { AttestationBootComposer } from './AttestationBootComposer.js';
import { AttestationBootState, attestationBootStateErrors } from './AttestationBootState.js';
import type { AttestationBootCheckpointStore } from './AttestationBootState.js';
import { BootManifestCoordinator } from './BootManifestCoordinator.js';
import type { BootManifestSecretLoaderPort } from './BootManifestCoordinator.js';
import { BootManifestVerifier, bootManifestVerificationErrors } from './BootManifestVerifier.js';
import type { BootManifestRuntimeIdentity, VerifiedBootManifest } from './BootManifestVerifier.js';
import { KmsSealedAttestationBootCheckpointStore } from './KmsSealedAttestationBootCheckpointStore.js';
import { verifySignedBootManifestKeyset } from '@folklore/nitro-attestation';
import type { BootSessionState, RuntimeEvidenceSessionPort } from './ports.js';
import { bootPrepareStepCode } from './boot-prepare-failure.js';

export const DEFAULT_ENCLAVE_ATTESTATION_PORT = 8101;
const RUNTIME_ATTESTATION_PREPARE_FAILED = 'runtime_attestation_prepare_failed';

type RuntimeAttestationEnv = Partial<Record<string, string | undefined>>;

interface RuntimeAttestationCompositionDeps {
  env: RuntimeAttestationEnv;
  secretLoader: BootManifestSecretLoaderPort;
  s3?: S3Client;
  checkpointStore?: AttestationBootCheckpointStore;
  logger?: Pick<Logger, 'warn'>;
}

type RuntimeAttestationLifecycleLogger = Pick<Logger, 'error'>;

interface RuntimeAttestationConfig {
  signedManifest: { manifest: BootManifest; raw: unknown };
  runtimeIdentity: BootManifestRuntimeIdentity;
  pinnedKeys: { signedKeyset: SignedBootManifestKeyset };
}

export class RuntimeAttestationComposition implements RuntimeEvidenceSessionPort {
  constructor(
    private readonly signedManifest: { manifest: BootManifest; raw: unknown },
    private readonly runtimeIdentity: BootManifestRuntimeIdentity,
    private readonly bootState: AttestationBootState,
    private readonly composer: AttestationBootComposer,
    private readonly verifier: BootManifestVerifier,
  ) {}

  #verifiedManifest: VerifiedBootManifest | undefined;

  async prepare(): Promise<void> {
    this.#verifiedManifest = await this.composer.prepare(
      this.signedManifest.raw,
      this.runtimeIdentity,
    );
  }

  runtimeEvidenceSession(): BootSessionState {
    if (!this.#verifiedManifest) throw new Error(attestationBootStateErrors.notVerified);
    if (!this.bootState.isKmsUnsealed()) throw new Error(attestationBootStateErrors.kmsNotReady);
    return this.verifier.bootSessionState();
  }

  verifiedManifest(): VerifiedBootManifest {
    if (!this.#verifiedManifest) throw new Error('runtime_attestation_not_prepared');
    return this.#verifiedManifest;
  }

  /** Content-free boot session identity for the evidence seam. */
  bootSessionState(): BootSessionState {
    return this.verifier.bootSessionState();
  }

  secretValue(id: string): string {
    return this.bootState.secretValue(id);
  }

  async signalKmsUnsealed(): Promise<void> {
    await this.bootState.markKmsUnsealed();
  }
}

// applyAssignments receives the prepared composition rather than reading the caller's own handle:
// enable/start later reassign that handle to null on failure, and a first boot after that must not
// mistake a verified manifest for an absent one.
export async function initializeRuntimeAttestationForBoot(
  composition: RuntimeAttestationComposition | null | undefined,
  applyAssignments: (prepared: RuntimeAttestationComposition | null) => Promise<void>,
  logger: RuntimeAttestationLifecycleLogger,
): Promise<RuntimeAttestationComposition | null> {
  const prepared = await prepareRuntimeAttestation(composition, logger);
  await applyAssignments(prepared);
  if (!prepared) return null;
  const signaled = await signalKmsUnsealed(prepared, logger);
  if (!signaled) throw new Error('runtime_attestation_kms_signal_failed');
  return signaled;
}

async function prepareRuntimeAttestation(
  composition: RuntimeAttestationComposition | null | undefined,
  logger: RuntimeAttestationLifecycleLogger,
): Promise<RuntimeAttestationComposition | null> {
  if (!composition) return null;
  try {
    await composition.prepare();
    return composition;
  } catch (error) {
    const code = bootPrepareStepCode(error, RUNTIME_ATTESTATION_PREPARE_FAILED);
    logger.error('RUNTIME_ATTESTATION_PREPARE_FAILED', {
      errorName: errorName(error),
      errorCode: code,
    });
    throw new Error(code);
  }
}

async function signalKmsUnsealed(
  composition: RuntimeAttestationComposition,
  logger: RuntimeAttestationLifecycleLogger,
): Promise<RuntimeAttestationComposition | null> {
  try {
    await composition.signalKmsUnsealed();
    return composition;
  } catch (error) {
    logger.error('RUNTIME_ATTESTATION_KMS_SIGNAL_FAILED', { errorName: errorName(error) });
    return null;
  }
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : 'unknown';
}

export function createRuntimeAttestationComposition(
  deps: RuntimeAttestationCompositionDeps,
): RuntimeAttestationComposition | undefined {
  const config = readRuntimeAttestationConfig(deps.env, deps.logger);
  if (!config) return undefined;

  const verifier = new BootManifestVerifier(config.pinnedKeys);
  const bootState = new AttestationBootState(
    new BootManifestCoordinator(verifier, deps.secretLoader),
    deps.checkpointStore ?? createPersistentCheckpointStore(config, deps.s3),
  );
  return new RuntimeAttestationComposition(
    config.signedManifest,
    config.runtimeIdentity,
    bootState,
    new AttestationBootComposer(bootState),
    verifier,
  );
}

function createPersistentCheckpointStore(
  config: RuntimeAttestationConfig,
  s3: S3Client | undefined,
): AttestationBootCheckpointStore {
  if (!s3) throw invalidConfig();
  return new KmsSealedAttestationBootCheckpointStore({
    s3,
    checkpointPrefix: config.runtimeIdentity.resourcePrefixes.sealedBlobsS3,
    kmsKeyId: config.runtimeIdentity.kmsKeyArn,
    orgId: config.runtimeIdentity.orgId,
    deploymentId: config.runtimeIdentity.deploymentId,
  });
}

function readRuntimeAttestationConfig(
  env: RuntimeAttestationEnv,
  logger: Pick<Logger, 'warn'> | undefined,
): RuntimeAttestationConfig | undefined {
  const signedManifestRaw = env['ENCLAVE_ATTESTATION_BOOT_MANIFEST'];
  const anyConfig = [
    signedManifestRaw,
    env['ENCLAVE_ATTESTATION_BOOT_KEYSET'],
    env['ENCLAVE_ATTESTATION_BOOT_KEYS'],
    env['CONTROL_PLANE_TLS_SPKI_SHA256'],
  ].some((value) => value !== undefined && value !== '');
  if (!anyConfig) return undefined;

  const missing = requiredConfigNames(env).filter((name) => !env[name]);
  if (!signedManifestRaw) missing.push('ENCLAVE_ATTESTATION_BOOT_MANIFEST');
  if (!env['ENCLAVE_ATTESTATION_BOOT_KEYSET']) {
    missing.push('ENCLAVE_ATTESTATION_BOOT_KEYSET');
  }
  if (missing.length > 0) {
    logger?.warn('runtime attestation boot config incomplete', { missing });
    throw invalidConfig();
  }

  return {
    signedManifest: readSignedManifest(signedManifestRaw),
    runtimeIdentity: readRuntimeIdentity(env),
    pinnedKeys: readPinnedKeys(env),
  };
}

function requiredConfigNames(env: RuntimeAttestationEnv): string[] {
  const names = new Set([
    'ORG_ID',
    'DEPLOYMENT_ID',
    'AWS_ACCOUNT_ID',
    'AWS_REGION',
    'KMS_KEY_ARN',
    'STORAGE_KEY_ARN',
    'SOURCE_SHA',
    'EIF_DIGEST',
    'CONFIGURATION_GENERATION',
  ]);
  if (
    env['CONTROL_PLANE_URL'] !== undefined ||
    env['CONTROL_PLANE_TLS_SPKI_SHA256'] !== undefined
  ) {
    names.add('CONTROL_PLANE_URL');
    names.add('CONTROL_PLANE_TLS_SPKI_SHA256');
  }
  if (!env['ENCLAVE_ATTESTATION_SEALED_BLOBS_PREFIX']) names.add('SEALED_BLOB_BUCKET');
  if (!env['ENCLAVE_ATTESTATION_RAW_PAYLOADS_PREFIX']) names.add('RAW_PAYLOADS_BUCKET');
  if (!env['ENCLAVE_ATTESTATION_PROCESSED_OUTPUTS_PREFIX']) {
    names.add('PROCESSED_OUTPUTS_BUCKET');
  }
  return [...names];
}

function readSignedManifest(raw: string | undefined): { manifest: BootManifest; raw: unknown } {
  const parsed = readJson(raw);
  try {
    parseBootManifestWire(parsed);
  } catch {
    if (signedBootManifestSchema.safeParse(parsed).success) {
      throw new Error(bootManifestVerificationErrors.legacyFormatRefused);
    }
    throw invalidConfig();
  }
  const manifest = (parsed as { manifest?: unknown }).manifest;
  const bootManifest = bootManifestSchema.safeParse(manifest);
  if (!bootManifest.success) throw invalidConfig();
  return { manifest: bootManifest.data, raw: parsed };
}

function readRuntimeIdentity(env: RuntimeAttestationEnv): BootManifestRuntimeIdentity {
  const orgId = requireEnv(env, 'ORG_ID');
  return {
    orgId,
    deploymentId: requireEnv(env, 'DEPLOYMENT_ID'),
    awsAccountId: requireEnv(env, 'AWS_ACCOUNT_ID'),
    awsRegion: requireEnv(env, 'AWS_REGION'),
    kmsKeyArn: requireEnv(env, 'KMS_KEY_ARN'),
    storageKeyArn: requireEnv(env, 'STORAGE_KEY_ARN'),
    resourcePrefixes: {
      sealedBlobsS3:
        env['ENCLAVE_ATTESTATION_SEALED_BLOBS_PREFIX'] ??
        s3Prefix(requireEnv(env, 'SEALED_BLOB_BUCKET'), `sealed-keys/${orgId}`),
      rawPayloadsS3:
        env['ENCLAVE_ATTESTATION_RAW_PAYLOADS_PREFIX'] ??
        s3Prefix(requireEnv(env, 'RAW_PAYLOADS_BUCKET'), `raw-payloads/${orgId}`),
      processedOutputsS3:
        env['ENCLAVE_ATTESTATION_PROCESSED_OUTPUTS_PREFIX'] ??
        s3Prefix(requireEnv(env, 'PROCESSED_OUTPUTS_BUCKET'), `processed-outputs/${orgId}`),
      tenantSsm: env['ENCLAVE_ATTESTATION_TENANT_SSM_PREFIX'] ?? `/folklore/${orgId}/`,
    },
    sourceSha: requireEnv(env, 'SOURCE_SHA'),
    eifDigest: requireEnv(env, 'EIF_DIGEST'),
    configurationGeneration: readConfigurationGeneration(env),
    ...(env['CONTROL_PLANE_URL'] !== undefined
      ? { controlPlaneIdentity: readControlPlaneIdentity(env) }
      : {}),
  };
}

function readControlPlaneIdentity(env: RuntimeAttestationEnv) {
  const pins = requireEnv(env, 'CONTROL_PLANE_TLS_SPKI_SHA256')
    .split(',')
    .map((pin) => pin.trim())
    .filter((pin) => pin.length > 0);
  const parsed = controlPlaneIdentitySchema.safeParse({
    origin: requireEnv(env, 'CONTROL_PLANE_URL'),
    tlsSpkiSha256: pins,
  });
  if (!parsed.success) throw invalidConfig();
  return parsed.data;
}

function readPinnedKeys(env: RuntimeAttestationEnv): { signedKeyset: SignedBootManifestKeyset } {
  const parsed = readJson(env['ENCLAVE_ATTESTATION_BOOT_KEYSET']);
  if (isRecord(parsed) && 'keyset' in parsed) {
    try {
      verifySignedBootManifestKeyset(parsed);
      const signedKeyset = signedBootManifestKeysetSchema.parse(parsed);
      return Object.freeze({ signedKeyset });
    } catch {
      throw invalidConfig();
    }
  }
  throw invalidConfig();
}

function readConfigurationGeneration(env: RuntimeAttestationEnv): number {
  const parsed = Number.parseInt(requireEnv(env, 'CONFIGURATION_GENERATION'), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw invalidConfig();
  return parsed;
}

function readJson(raw: string | undefined): unknown {
  if (!raw) throw invalidConfig();
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw invalidConfig();
  }
}

function requireEnv(env: RuntimeAttestationEnv, name: string): string {
  const value = env[name];
  if (!value) throw invalidConfig();
  return value;
}

function s3Prefix(bucket: string, keyPrefix: string): string {
  return `s3://${bucket}/${keyPrefix.replace(/^\/+|\/+$/g, '')}/`;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function invalidConfig(): ConfigurationError {
  return new ConfigurationError('runtime attestation boot config invalid', {
    component: 'enclave-attestation',
  });
}
