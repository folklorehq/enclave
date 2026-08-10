import { createHash } from 'node:crypto';
import type { BootManifestCoordinatorResult } from './BootManifestCoordinator.js';
import type { LoadedBootManifestSecret } from './BootManifestSecretLoader.js';
import type { BootManifestRuntimeIdentity, VerifiedBootManifest } from './BootManifestVerifier.js';

export const attestationBootStateErrors = {
  notVerified: 'attestation_boot_not_verified',
  kmsNotReady: 'attestation_boot_kms_not_ready',
  checkpointInvalid: 'attestation_boot_checkpoint_invalid',
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
    await this.writeCheckpoint(this.checkpoint('manifest_verified', prepared.manifest));
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
    return Object.freeze({
      bootManifestVerified: this.#prepared !== undefined,
      kmsUnsealed: this.#kmsUnsealed,
      hasInProcessSecrets: this.#prepared !== undefined && this.#prepared.secrets.length > 0,
      inProcessGeneration: this.#inProcessGeneration,
      checkpoint,
    });
  }

  private async readCheckpoint(): Promise<AttestationBootCheckpoint | null> {
    let checkpoint: unknown;
    try {
      checkpoint = await this.store.read();
    } catch {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
    if (checkpoint === null) return null;
    if (!this.isCheckpoint(checkpoint)) {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
    }
    return this.ownCheckpoint(checkpoint);
  }

  private async writeCheckpoint(checkpoint: AttestationBootCheckpoint): Promise<void> {
    try {
      await this.store.write(checkpoint);
    } catch {
      throw this.failure(attestationBootStateErrors.checkpointInvalid);
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
    return Object.freeze({
      ...manifest,
      resourcePrefixes: Object.freeze({ ...manifest.resourcePrefixes }),
      secretReferences,
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

  private isCheckpoint(value: unknown): value is AttestationBootCheckpoint {
    if (!value || typeof value !== 'object') return false;
    const checkpoint = value as Partial<Record<keyof AttestationBootCheckpoint, unknown>>;
    return (
      checkpoint.version === 1 &&
      (checkpoint.phase === 'manifest_verified' || checkpoint.phase === 'kms_unsealed') &&
      typeof checkpoint.orgId === 'string' &&
      typeof checkpoint.deploymentId === 'string' &&
      Number.isSafeInteger(checkpoint.configurationGeneration) &&
      typeof checkpoint.manifestHash === 'string' &&
      /^[0-9a-f]{64}$/.test(checkpoint.manifestHash) &&
      typeof checkpoint.recordedAt === 'string' &&
      Number.isFinite(Date.parse(checkpoint.recordedAt))
    );
  }

  private failure(code: AttestationBootStateError): Error {
    return new Error(code);
  }
}

const systemClock: AttestationBootClock = {
  now(): Date {
    return new Date();
  },
};
