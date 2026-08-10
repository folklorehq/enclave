import type { Logger } from '@folklore/core';
import {
  controlPlaneIdentitySchema,
  signedBootManifestSchema,
  signedBootManifestKeysetSchema,
  type BootManifest,
  type SignedBootManifestKeyset,
  type SignedBootManifest,
} from '@folklore/contracts/enclave-attestation';
import { ConfigurationError } from '@folklore/errors';
import { AttestationBootComposer } from './AttestationBootComposer.js';
import { AttestationBootState } from './AttestationBootState.js';
import type { AttestationBootCheckpointStore } from './AttestationBootState.js';
import { BootManifestCoordinator } from './BootManifestCoordinator.js';
import type { BootManifestSecretLoaderPort } from './BootManifestCoordinator.js';
import { BootManifestVerifier } from './BootManifestVerifier.js';
import type { BootManifestRuntimeIdentity, VerifiedBootManifest } from './BootManifestVerifier.js';
import { InMemoryAttestationBootCheckpointStore } from './InMemoryAttestationBootCheckpointStore.js';
import { NodeRuntimeAttestationListener } from './NodeRuntimeAttestationListener.js';
import { RuntimeAttestationService } from './RuntimeAttestationService.js';
import type {
  RuntimeAttestationReadiness,
  RuntimeAttestationReadinessSnapshot,
} from './RuntimeAttestationService.js';
import type {
  RuntimeAttestationListener,
  RuntimeAttestationServerOptions,
} from './RuntimeAttestationServer.js';
import type { NsmAttestationPort } from '../sealing/nsm.js';
import { verifySignedBootManifestKeyset } from '@folklore/nitro-attestation';
import {
  BOOT_MANIFEST_ROOT_KEY_ID,
  BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
  assertApprovedBootManifestRoot,
} from './boot-manifest-root.js';

export const DEFAULT_ENCLAVE_ATTESTATION_PORT = 8101;

type RuntimeAttestationEnv = Partial<Record<string, string | undefined>>;

interface CloseableRuntimeAttestationListener extends RuntimeAttestationListener {
  close?(): Promise<void>;
}

export interface RuntimeAttestationCompositionDeps {
  env: RuntimeAttestationEnv;
  secretLoader: BootManifestSecretLoaderPort;
  nsm: NsmAttestationPort;
  isTenantAssigned(): boolean;
  isTenantApiReady(): boolean;
  getIngestPublicKey?(): Uint8Array | Promise<Uint8Array>;
  listener?: CloseableRuntimeAttestationListener;
  checkpointStore?: AttestationBootCheckpointStore;
  logger?: Pick<Logger, 'info' | 'warn'>;
  serverOptions?: RuntimeAttestationServerOptions;
}

export type RuntimeAttestationLifecycleLogger = Pick<Logger, 'error'>;

interface RuntimeAttestationConfig {
  signedManifest: SignedBootManifest;
  runtimeIdentity: BootManifestRuntimeIdentity;
  pinnedKeys: { signedKeyset: SignedBootManifestKeyset };
  port: number;
}

export class RuntimeAttestationComposition {
  constructor(
    private readonly signedManifest: SignedBootManifest,
    private readonly runtimeIdentity: BootManifestRuntimeIdentity,
    private readonly bootState: AttestationBootState,
    private readonly composer: AttestationBootComposer,
    private readonly listener: CloseableRuntimeAttestationListener,
    private readonly logger?: Pick<Logger, 'info'>,
  ) {}

  #verifiedManifest: VerifiedBootManifest | undefined;

  async prepare(): Promise<void> {
    this.#verifiedManifest = await this.composer.prepare(this.signedManifest, this.runtimeIdentity);
  }

  verifiedManifest(): VerifiedBootManifest {
    if (!this.#verifiedManifest) throw new Error('runtime_attestation_not_prepared');
    return this.#verifiedManifest;
  }

  async markKmsUnsealed(unseal: () => Promise<void>): Promise<void> {
    await this.bootState.unsealWithKms(unseal);
  }

  async signalKmsUnsealed(): Promise<void> {
    await this.bootState.markKmsUnsealed();
  }

  async enable(): Promise<void> {
    await this.composer.enableRuntimeAttestation();
  }

  async start(): Promise<void> {
    await this.composer.start(this.listener);
    this.logger?.info('runtime attestation listener started');
  }

  signAssignmentAck(payload: Uint8Array): { publicKey: Uint8Array; signature: Uint8Array } {
    return this.composer.sign(payload);
  }

  async close(): Promise<void> {
    await this.listener.close?.();
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

export async function enableRuntimeAttestation(
  composition: RuntimeAttestationComposition | null | undefined,
  logger: RuntimeAttestationLifecycleLogger,
): Promise<RuntimeAttestationComposition | null> {
  if (!composition) return null;
  try {
    await composition.enable();
    return composition;
  } catch (error) {
    logger.error('RUNTIME_ATTESTATION_ENABLE_FAILED', { errorName: errorName(error) });
    return null;
  }
}

export async function startRuntimeAttestation(
  composition: RuntimeAttestationComposition | null | undefined,
  logger: RuntimeAttestationLifecycleLogger,
): Promise<RuntimeAttestationComposition | null> {
  if (!composition) return null;
  try {
    await composition.start();
    return composition;
  } catch (error) {
    logger.error('RUNTIME_ATTESTATION_START_FAILED', { errorName: errorName(error) });
    return null;
  }
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
    logger.error('RUNTIME_ATTESTATION_PREPARE_FAILED', { errorName: errorName(error) });
    throw new Error('runtime_attestation_prepare_failed');
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

  const bootState = new AttestationBootState(
    new BootManifestCoordinator(new BootManifestVerifier(config.pinnedKeys), deps.secretLoader),
    deps.checkpointStore ?? new InMemoryAttestationBootCheckpointStore(),
  );
  const readiness = new CompositionReadiness(
    bootState,
    config.signedManifest.manifest,
    deps.isTenantAssigned,
    deps.isTenantApiReady,
    deps.getIngestPublicKey,
  );
  const service = new RuntimeAttestationService(readiness, deps.nsm, {
    now: () => new Date(),
  });
  const listener = deps.listener ?? new NodeRuntimeAttestationListener(config.port);
  return new RuntimeAttestationComposition(
    config.signedManifest,
    config.runtimeIdentity,
    bootState,
    new AttestationBootComposer(bootState, service, deps.serverOptions),
    listener,
    deps.logger,
  );
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
    port: readPort(env['ENCLAVE_ATTESTATION_PORT']),
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

function readSignedManifest(raw: string | undefined): SignedBootManifest {
  const parsed = signedBootManifestSchema.safeParse(readJson(raw));
  if (!parsed.success) throw invalidConfig();
  return parsed.data;
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
      assertApprovedBootManifestRoot();
      verifySignedBootManifestKeyset(
        parsed,
        BOOT_MANIFEST_ROOT_KEY_ID,
        BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
        readMinimumKeysetGeneration(env),
      );
      const signedKeyset = signedBootManifestKeysetSchema.parse(parsed);
      return Object.freeze({ signedKeyset });
    } catch {
      throw invalidConfig();
    }
  }
  throw invalidConfig();
}

function readMinimumKeysetGeneration(env: RuntimeAttestationEnv): number {
  const raw = env['ENCLAVE_ATTESTATION_MIN_KEYSET_GENERATION'];
  if (!raw) return 1;
  const generation = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(generation) || generation < 1) throw invalidConfig();
  return generation;
}

function readConfigurationGeneration(env: RuntimeAttestationEnv): number {
  const parsed = Number.parseInt(requireEnv(env, 'CONFIGURATION_GENERATION'), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw invalidConfig();
  return parsed;
}

function readPort(raw: string | undefined): number {
  if (!raw) return DEFAULT_ENCLAVE_ATTESTATION_PORT;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) throw invalidConfig();
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

class CompositionReadiness implements RuntimeAttestationReadiness {
  constructor(
    private readonly bootState: AttestationBootState,
    private readonly manifest: BootManifest,
    private readonly isTenantAssigned: () => boolean,
    private readonly isTenantApiReady: () => boolean,
    private readonly ingestPublicKey?: () => Uint8Array | Promise<Uint8Array>,
  ) {}

  getIngestPublicKey(): Uint8Array | Promise<Uint8Array> {
    if (!this.ingestPublicKey) return Uint8Array.from([]);
    return this.ingestPublicKey();
  }

  async getReadiness(): Promise<RuntimeAttestationReadinessSnapshot> {
    const bootReadiness = await this.bootState.getReadiness();
    return {
      manifest: this.manifest,
      tenantAssigned: this.isTenantAssigned(),
      bootManifestVerified: bootReadiness.bootManifestVerified,
      kmsUnsealed: bootReadiness.kmsUnsealed,
      tenantApiReady: this.isTenantApiReady(),
    };
  }
}
