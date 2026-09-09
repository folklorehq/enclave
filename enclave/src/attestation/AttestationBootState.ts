import { createHash } from 'node:crypto';
import type { BootManifestCoordinatorResult } from './BootManifestCoordinator.js';
import type { LoadedBootManifestSecret } from './BootManifestSecretLoader.js';
import type { BootManifestRuntimeIdentity, VerifiedBootManifest } from './BootManifestVerifier.js';

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;

export const attestationBootStateErrors = {
  notVerified: 'attestation_boot_not_verified',
  kmsNotReady: 'attestation_boot_kms_not_ready',
  checkpointInvalid: 'attestation_boot_checkpoint_invalid',
  checkpointSuperseded: 'attestation_boot_checkpoint_superseded',
  checkpointConflict: 'attestation_boot_checkpoint_conflict',
} as const;

type AttestationBootStateError =
  (typeof attestationBootStateErrors)[keyof typeof attestationBootStateErrors];

export type AttestationBootCheckpointPhase = 'manifest_verified' | 'kms_unsealed';

export type AttestationBootCheckpoint = Readonly<{
  version: 1;
  phase: AttestationBootCheckpointPhase;
  orgId: string;
  deploymentId: string;
  configurationGeneration: number;
  manifestHash: string;
  recordedAt: string;
}>;

export interface AttestationBootCheckpointStore {
  read(): Promise<AttestationBootCheckpoint | null>;
  write(checkpoint: AttestationBootCheckpoint): Promise<void>;
}

export function parseAttestationBootCheckpoint(value: unknown): AttestationBootCheckpoint {
  if (!isAttestationBootCheckpoint(value)) {
    throw new Error(attestationBootStateErrors.checkpointInvalid);
  }
  return Object.freeze({ ...value });
}

export interface AttestationBootManifestCoordinatorPort {
  verifyAndLoad(
    input: unknown,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): Promise<BootManifestCoordinatorResult>;
}

export interface AttestationBootClock {
  now(): Date;
}

export type AttestationBootReadinessSnapshot = Readonly<{
  bootManifestVerified: boolean;
  kmsUnsealed: boolean;
  hasInProcessSecrets: boolean;
  inProcessGeneration: number;
  checkpoint: AttestationBootCheckpoint | null;
}>;

export class AttestationBootState {
  #prepared: BootManifestCoordinatorResult | undefined;
  #kmsUnsealed = false;
  #inProcessGeneration = 0;

  constructor(
    private readonly coordinator: AttestationBootManifestCoordinatorPort,
    private readonly store: AttestationBootCheckpointStore,
    private readonly clock: AttestationBootClock = systemClock,
  ) {}

  async prepareManifest(
    signedInput: unknown,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): Promise<BootManifestCoordinatorResult> {
    this.clear();
    const prepared = this.ownResult(
      await this.coordinator.verifyAndLoad(signedInput, runtimeIdentity),
    );
    const candidateCheckpoint = this.checkpoint('manifest_verified', prepared.manifest);
    const persisted = await this.readCheckpoint();
    this.assertCheckpointAcceptsManifest(persisted, candidateCheckpoint);
    await this.writeCheckpoint(candidateCheckpoint);
    this.#prepared = prepared;
    this.#kmsUnsealed = false;
    return prepared;
  }

  clear(): void {
    this.#prepared = undefined;
    this.#kmsUnsealed = false;
    this.#inProcessGeneration += 1;
  }

  async unsealWithKms(unseal: () => Promise<void>): Promise<void> {
    const prepared = this.#prepared;
    if (prepared === undefined) throw this.failure(attestationBootStateErrors.notVerified);
    try {
      await unseal();
    } catch {
      throw this.failure(attestationBootStateErrors.kmsNotReady);
    }
    await this.markKmsUnsealed();
  }

  async markKmsUnsealed(): Promise<void> {
    const prepared = this.#prepared;
    if (prepared === undefined) throw this.failure(attestationBootStateErrors.notVerified);
    await this.writeCheckpoint(this.checkpoint('kms_unsealed', prepared.manifest));
    this.#kmsUnsealed = true;
  }

  async getReadiness(): Promise<AttestationBootReadinessSnapshot> {
    const checkpoint = await this.readCheckpoint();
    const prepared = this.#prepared;
    if (prepared !== undefined) {
      this.assertCheckpointMatchesManifest(
        checkpoint,
        this.checkpoint('manifest_verified', prepared.manifest),
      );
    }
    return Object.freeze({
      bootManifestVerified: prepared !== undefined,
      kmsUnsealed: this.#kmsUnsealed,
      hasInProcessSecrets: prepared !== undefined && prepared.secrets.length > 0,
      inProcessGeneration: this.#inProcessGeneration,
      checkpoint,
    });
  }

  secretValue(id: string): string {
    const prepared = this.#prepared;
    if (prepared === undefined) throw this.failure(attestationBootStateErrors.notVerified);
    const secret = prepared.secrets.find((candidate) => candidate.id === id);
    if (!secret) throw this.failure(attestationBootStateErrors.notVerified);
    return secret.value;
  }

  private async readCheckpoint(): Promise<AttestationBootCheckpoint | null> {
    let checkpoint: unknown;
    try {
      checkpoint = await this.store.read();
    } catch {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
    if (checkpoint === null) return null;
    try {
      return this.ownCheckpoint(parseAttestationBootCheckpoint(checkpoint));
    } catch {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
  }

  private async writeCheckpoint(checkpoint: AttestationBootCheckpoint): Promise<void> {
    try {
      await this.store.write(checkpoint);
    } catch {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
  }

  private assertCheckpointAcceptsManifest(
    persisted: AttestationBootCheckpoint | null,
    candidate: AttestationBootCheckpoint,
  ): void {
    if (persisted === null) return;
    if (persisted.orgId !== candidate.orgId || persisted.deploymentId !== candidate.deploymentId) {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
    if (persisted.configurationGeneration > candidate.configurationGeneration) {
      throw this.failure(attestationBootStateErrors.checkpointSuperseded);
    }
    if (
      persisted.configurationGeneration === candidate.configurationGeneration &&
      persisted.manifestHash !== candidate.manifestHash
    ) {
      throw this.failure(attestationBootStateErrors.checkpointConflict);
    }
  }

  private assertCheckpointMatchesManifest(
    persisted: AttestationBootCheckpoint | null,
    candidate: AttestationBootCheckpoint,
  ): void {
    if (persisted === null) throw this.failure(attestationBootStateErrors.checkpointInvalid);
    if (persisted.orgId !== candidate.orgId || persisted.deploymentId !== candidate.deploymentId) {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
    if (persisted.configurationGeneration > candidate.configurationGeneration) {
      throw this.failure(attestationBootStateErrors.checkpointSuperseded);
    }
    if (persisted.configurationGeneration < candidate.configurationGeneration) {
      throw this.failure(attestationBootStateErrors.checkpointSuperseded);
    }
    if (persisted.manifestHash !== candidate.manifestHash) {
      throw this.failure(attestationBootStateErrors.checkpointConflict);
    }
  }

  private checkpoint(
    phase: AttestationBootCheckpointPhase,
    manifest: VerifiedBootManifest,
  ): AttestationBootCheckpoint {
    const observedAt = this.clock.now();
    if (!Number.isFinite(observedAt.getTime())) {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
    return Object.freeze({
      version: 1,
      phase,
      orgId: manifest.orgId,
      deploymentId: manifest.deploymentId,
      configurationGeneration: manifest.configurationGeneration,
      manifestHash: this.manifestHash(manifest),
      recordedAt: observedAt.toISOString(),
    });
  }

  private manifestHash(manifest: VerifiedBootManifest): string {
    return createHash('sha256')
      .update(JSON.stringify(this.manifestHashPayload(manifest)))
      .digest('hex');
  }

  private manifestHashPayload(manifest: VerifiedBootManifest): readonly unknown[] {
    return [
      'folklore.attestation-boot-state.manifest.v1',
      manifest.version,
      manifest.signerKeyId,
      manifest.orgId,
      manifest.deploymentId,
      manifest.awsAccountId,
      manifest.awsRegion,
      manifest.kmsKeyArn,
      manifest.storageKeyArn,
      [
        manifest.resourcePrefixes.sealedBlobsS3,
        manifest.resourcePrefixes.rawPayloadsS3,
        manifest.resourcePrefixes.processedOutputsS3,
        manifest.resourcePrefixes.tenantSsm,
      ],
      manifest.sourceSha,
      manifest.eifDigest,
      manifest.configurationGeneration,
      manifest.secretReferences.map((reference) =>
        reference.store === 'secrets-manager'
          ? [reference.store, reference.id, reference.arn, reference.versionId]
          : [reference.store, reference.id, reference.path, reference.version],
      ),
      manifest.inferenceAttestation ?? null,
      manifest.inferenceTrustPolicy ?? null,
      ...(manifest.providerInferenceTrustPolicy
        ? [['providerInferenceTrustPolicy', manifest.providerInferenceTrustPolicy]]
        : []),
      manifest.assignmentManifestPublicKeySpki ?? null,
      manifest.enclaveOutputKey
        ? [
            manifest.enclaveOutputKey.keyId,
            manifest.enclaveOutputKey.publicKeySpki,
            manifest.enclaveOutputKey.privateKeySecretReferenceId,
            manifest.enclaveOutputKeyKmsKeyArn,
          ]
        : null,
      // Two manifests differing only in the recovery key must not checkpoint as the same boot.
      manifest.recoveryPubkey ?? null,
    ];
  }

  private ownResult(result: BootManifestCoordinatorResult): BootManifestCoordinatorResult {
    return Object.freeze({
      manifest: this.ownManifest(result.manifest),
      secrets: this.ownSecrets(result.secrets),
    });
  }

  private ownManifest(manifest: VerifiedBootManifest): VerifiedBootManifest {
    const secretReferences: VerifiedBootManifest['secretReferences'] = Object.freeze(
      manifest.secretReferences.map((reference) => Object.freeze({ ...reference })),
    );
    const inferenceAttestation = manifest.inferenceAttestation
      ? Object.freeze({
          ...manifest.inferenceAttestation,
          modelAllowlist: Object.freeze([...manifest.inferenceAttestation.modelAllowlist]),
        })
      : undefined;
    const providerInferenceTrustPolicy = manifest.providerInferenceTrustPolicy
      ? this.deepFreeze(manifest.providerInferenceTrustPolicy)
      : undefined;
    return Object.freeze({
      ...manifest,
      resourcePrefixes: Object.freeze({ ...manifest.resourcePrefixes }),
      secretReferences,
      ...(inferenceAttestation ? { inferenceAttestation } : {}),
      ...(providerInferenceTrustPolicy ? { providerInferenceTrustPolicy } : {}),
    });
  }

  private ownSecrets(
    secrets: readonly LoadedBootManifestSecret[],
  ): readonly LoadedBootManifestSecret[] {
    return Object.freeze(secrets.map((secret) => Object.freeze({ ...secret })));
  }

  private ownCheckpoint(checkpoint: AttestationBootCheckpoint): AttestationBootCheckpoint {
    return Object.freeze({ ...checkpoint });
  }

  private deepFreeze<T>(value: T): DeepReadonly<T> {
    if (value && typeof value === 'object') {
      Object.freeze(value);
      for (const child of Object.values(value as Record<string, unknown>)) this.deepFreeze(child);
    }
    return value as DeepReadonly<T>;
  }

  private failure(code: AttestationBootStateError): Error {
    return new Error(code);
  }
}

function isAttestationBootCheckpoint(value: unknown): value is AttestationBootCheckpoint {
  if (!value || typeof value !== 'object') return false;
  const checkpoint = value as Partial<Record<keyof AttestationBootCheckpoint, unknown>>;
  return (
    checkpoint.version === 1 &&
    (checkpoint.phase === 'manifest_verified' || checkpoint.phase === 'kms_unsealed') &&
    typeof checkpoint.orgId === 'string' &&
    checkpoint.orgId.length > 0 &&
    typeof checkpoint.deploymentId === 'string' &&
    checkpoint.deploymentId.length > 0 &&
    typeof checkpoint.configurationGeneration === 'number' &&
    Number.isSafeInteger(checkpoint.configurationGeneration) &&
    checkpoint.configurationGeneration > 0 &&
    typeof checkpoint.manifestHash === 'string' &&
    /^[0-9a-f]{64}$/.test(checkpoint.manifestHash) &&
    typeof checkpoint.recordedAt === 'string' &&
    Number.isFinite(Date.parse(checkpoint.recordedAt))
  );
}

const systemClock: AttestationBootClock = {
  now(): Date {
    return new Date();
  },
};
