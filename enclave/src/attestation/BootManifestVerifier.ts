import { createHash, createPublicKey, KeyObject, verify } from 'node:crypto';
import {
  parseBootManifestWire,
  generationHighWaterRuntimeConfigV1Schema,
  type BootManifest,
  type BootManifestResourcePrefixes,
  type BootManifestKeyset,
  type SignedBootManifestKeyset,
  type ControlPlaneIdentity,
  type ParsedBootManifestWire,
} from '@folklore/contracts/enclave-attestation';
import { buildSignerPurposeSignatureMessage } from '@folklore/contracts';
import {
  encodeBootManifest,
  encodeBootManifestSubjectV3,
  digestCanonicalCbor,
  hashBootManifestKeyset,
  verifySignedBootManifestKeyset,
  TRUSTED_SIGNER_RECOVERY_ROOT_DIGEST,
  recoveryRootInstallationReportV1Schema,
  type RecoveryRootInstallationReportV1,
} from '@folklore/nitro-attestation';
import { DstackEvidenceAdapter, unavailableResult } from './DstackEvidenceAdapter.js';
import type {
  DstackNativeVerificationInputV1,
  DstackNativeVerificationResultV1,
  DstackNativeVerifierPort,
} from './DstackNativeVerifier.js';

export type PinnedBootManifestKeyStatus = 'active' | 'verification-only' | 'disabled' | 'revoked';

export interface PinnedBootManifestKey {
  keyId: string;
  status: PinnedBootManifestKeyStatus;
  publicKey: KeyObject;
}

export interface BootManifestVerifierOptions {
  dstackVerifier?: DstackNativeVerifierPort;
}

export interface BootManifestRuntimeIdentity {
  orgId: string;
  deploymentId: string;
  awsAccountId: string;
  awsRegion: string;
  /** Master CMK — the attestation-gated seal/unseal key. */
  kmsKeyArn: string;
  /** Storage key — the unattested key the enclave's content ESDK keyring must be built from. */
  storageKeyArn: string;
  resourcePrefixes: BootManifestResourcePrefixes;
  sourceSha: string;
  eifDigest: string;
  configurationGeneration: number;
  controlPlaneIdentity?: ControlPlaneIdentity;
}

type FrozenControlPlaneIdentity = Omit<ControlPlaneIdentity, 'tlsSpkiSha256'> & {
  readonly tlsSpkiSha256: readonly string[];
};

type FrozenInferenceTrustPolicy = Omit<
  NonNullable<BootManifest['inferenceTrustPolicy']>,
  | 'redirectOrigins'
  | 'tlsSpkiSha256'
  | 'quoteRootDigests'
  | 'workloadMeasurements'
  | 'attestationKeys'
  | 'receiptKeys'
  | 'permittedModels'
  | 'roleModels'
> & {
  readonly redirectOrigins: readonly string[];
  readonly tlsSpkiSha256: readonly string[];
  readonly quoteRootDigests: readonly string[];
  readonly workloadMeasurements: readonly string[];
  readonly attestationKeys: readonly Readonly<
    NonNullable<BootManifest['inferenceTrustPolicy']>['attestationKeys'][number]
  >[];
  readonly receiptKeys: readonly Readonly<
    NonNullable<BootManifest['inferenceTrustPolicy']>['receiptKeys'][number]
  >[];
  readonly permittedModels: readonly Readonly<
    NonNullable<BootManifest['inferenceTrustPolicy']>['permittedModels'][number]
  >[];
  readonly roleModels: Readonly<NonNullable<BootManifest['inferenceTrustPolicy']>['roleModels']>;
};
type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;
type FrozenProviderInferenceTrustPolicy = DeepReadonly<
  NonNullable<BootManifest['providerInferenceTrustPolicy']>
>;

export type VerifiedBootManifest = Readonly<
  Omit<
    BootManifest,
    | 'resourcePrefixes'
    | 'secretReferences'
    | 'oauthProviders'
    | 'controlPlaneIdentity'
    | 'inferenceTrustPolicy'
    | 'inferenceAttestation'
    | 'providerInferenceTrustPolicy'
  >
> & {
  readonly resourcePrefixes: Readonly<BootManifestResourcePrefixes>;
  readonly secretReferences: readonly Readonly<BootManifest['secretReferences'][number]>[];
  readonly oauthProviders: readonly Readonly<
    Omit<
      BootManifest['oauthProviders'][number],
      'allowedHosts' | 'jiraWebhookPilotOrgIds' | 'jiraWebhookClaimPolicy'
    > & {
      readonly allowedHosts: readonly string[];
      readonly jiraWebhookPilotOrgIds?: readonly string[];
      readonly jiraWebhookClaimPolicy?: Readonly<
        NonNullable<BootManifest['oauthProviders'][number]['jiraWebhookClaimPolicy']>
      >;
    }
  >[];
  readonly controlPlaneIdentity?: FrozenControlPlaneIdentity;
  readonly inferenceTrustPolicy?: FrozenInferenceTrustPolicy;
  readonly inferenceAttestation?: Readonly<
    Omit<NonNullable<BootManifest['inferenceAttestation']>, 'modelAllowlist'> & {
      readonly modelAllowlist: readonly string[];
    }
  >;
  readonly providerInferenceTrustPolicy?: FrozenProviderInferenceTrustPolicy;
};

export const bootManifestVerificationErrors = {
  invalid: 'boot_manifest_invalid',
  keySet: 'boot_manifest_keyset_invalid',
  signer: 'boot_manifest_signer_invalid',
  signature: 'boot_manifest_signature_invalid',
  identity: 'boot_manifest_identity_invalid',
} as const;

export class BootManifestVerifier {
  readonly #keysById: ReadonlyMap<string, PinnedBootManifestKey>;
  readonly #dstackEvidenceAdapter: DstackEvidenceAdapter | undefined;
  readonly #keysetGeneration: number;
  readonly #keysetDigest: string;

  constructor(
    pinnedKeys: readonly PinnedBootManifestKey[] | { signedKeyset: SignedBootManifestKeyset },
    options: BootManifestVerifierOptions = {},
  ) {
    if (Array.isArray(pinnedKeys)) throw new Error(bootManifestVerificationErrors.keySet);
    if (!pinnedKeys || typeof pinnedKeys !== 'object' || !('signedKeyset' in pinnedKeys)) {
      throw new Error(bootManifestVerificationErrors.keySet);
    }
    const config = pinnedKeys as { signedKeyset: SignedBootManifestKeyset };
    const keyset = verifySignedBootManifestKeyset(config.signedKeyset);
    this.#keysById = this.createKeySet(this.keysFromSignedKeyset(keyset));
    this.#keysetGeneration = keyset.generation;
    this.#keysetDigest = hashBootManifestKeyset(keyset);
    this.#dstackEvidenceAdapter = options.dstackVerifier
      ? new DstackEvidenceAdapter(options.dstackVerifier)
      : undefined;
  }

  verify(input: unknown, runtimeIdentity: BootManifestRuntimeIdentity): VerifiedBootManifest {
    let parsed: ParsedBootManifestWire;
    try {
      parsed = parseBootManifestWire(input);
    } catch {
      throw new Error(bootManifestVerificationErrors.invalid);
    }
    switch (parsed.wire) {
      case 'LegacySignedBootManifestV2':
        return this.verifyV2(parsed, runtimeIdentity);
      case 'SignedBootManifestV3':
        return this.verifyV3(parsed, runtimeIdentity);
    }
  }

  verifyGenerationHighWaterRuntimeConfig(
    manifest: VerifiedBootManifest,
    required: boolean,
  ): VerifiedBootManifest['generationHighWaterRuntimeConfig'] {
    const config = manifest.generationHighWaterRuntimeConfig;
    if (!config && required) throw new Error('generation_high_water_runtime_config_missing');
    if (!config) return undefined;
    const parsed = generationHighWaterRuntimeConfigV1Schema.safeParse(config);
    if (!parsed.success) throw new Error('generation_high_water_runtime_config_invalid');
    return Object.freeze(parsed.data);
  }

  private verifyV2(
    parsed: Extract<ParsedBootManifestWire, { wire: 'LegacySignedBootManifestV2' }>,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): VerifiedBootManifest {
    const key = this.#keysById.get(parsed.signed.manifest.signerKeyId);
    if (!key || (key.status !== 'active' && key.status !== 'verification-only')) {
      throw new Error(bootManifestVerificationErrors.signer);
    }
    const isValid = verify(
      null,
      encodeBootManifest(parsed.signed.manifest),
      key.publicKey,
      Buffer.from(parsed.signed.signature, 'base64'),
    );
    if (!isValid) throw new Error(bootManifestVerificationErrors.signature);
    if (!this.matchesRuntimeIdentity(parsed.signed.manifest, runtimeIdentity)) {
      throw new Error(bootManifestVerificationErrors.identity);
    }
    this.assertProviderPolicyPrerequisites(parsed.signed.manifest);
    // The v2 signature (encodeBootManifest / encodeManifestFields) does NOT cover
    // inferenceCommissioning, so a parent could graft the marker onto a valid v2 pins-only
    // envelope and disable receipt verification. The commissioning marker is v3-only (its
    // full-JSON subject hash covers every field); reject it on the legacy path. Fail closed.
    if (parsed.signed.manifest.inferenceCommissioning !== undefined) {
      throw new Error(bootManifestVerificationErrors.invalid);
    }
    return this.freezeOwnedManifest(parsed.signed.manifest);
  }

  private verifyV3(
    parsed: Extract<ParsedBootManifestWire, { wire: 'SignedBootManifestV3' }>,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): VerifiedBootManifest {
    const envelope = parsed.signed;
    const key = this.#keysById.get(envelope.manifest.signerKeyId);
    if (!key || (key.status !== 'active' && key.status !== 'verification-only')) {
      throw new Error(bootManifestVerificationErrors.signer);
    }
    if (envelope.keyId !== key.keyId) throw new Error(bootManifestVerificationErrors.invalid);
    if (envelope.keysetGeneration !== this.#keysetGeneration) {
      throw new Error(bootManifestVerificationErrors.keySet);
    }
    if (envelope.keysetDigest !== this.#keysetDigest) {
      throw new Error(bootManifestVerificationErrors.keySet);
    }
    if (this.publicKeyFingerprint(key.publicKey) !== envelope.publicKeyFingerprint) {
      throw new Error(bootManifestVerificationErrors.signer);
    }
    const subjectBytes = encodeBootManifestSubjectV3({
      manifest: envelope.manifest,
      scope: envelope.scope,
    });
    if (digestCanonicalCbor(subjectBytes) !== envelope.subjectDigest) {
      throw new Error(bootManifestVerificationErrors.signature);
    }
    const message = buildSignerPurposeSignatureMessage(
      'boot-manifest',
      envelope.domain,
      Buffer.from(envelope.subjectDigest, 'hex'),
    );
    const isValid = verify(null, message, key.publicKey, Buffer.from(envelope.signature, 'base64'));
    if (!isValid) throw new Error(bootManifestVerificationErrors.signature);
    if (!this.matchesRuntimeIdentity(envelope.manifest, runtimeIdentity)) {
      throw new Error(bootManifestVerificationErrors.identity);
    }
    this.assertProviderPolicyPrerequisites(envelope.manifest);
    return this.freezeOwnedManifest(envelope.manifest);
  }

  /** The installed recovery-root digest this verifier reports before any future unfreeze. */
  installedRecoveryRootDigest(): string {
    return TRUSTED_SIGNER_RECOVERY_ROOT_DIGEST;
  }

  /** Content-free boot session identity for the evidence seam. */
  bootSessionState(): { sessionId: string; bootEpoch: number } {
    return {
      sessionId: createHash('sha256')
        .update(`${this.#keysetDigest}\u0000${this.#keysetGeneration}`)
        .digest('hex'),
      bootEpoch: this.#keysetGeneration,
    };
  }

  /** Reader installation report for the recovery-root update gate; requires configured build identity. */
  recoveryInstallationReport(): RecoveryRootInstallationReportV1 {
    const buildId = process.env['ENCLAVE_ATTESTATION_BUILD_ID']?.trim();
    const sourceCommit = process.env['ENCLAVE_ATTESTATION_SOURCE_SHA']?.trim();
    const artifactDigest = process.env['ENCLAVE_ATTESTATION_ARTIFACT_DIGEST']?.trim();
    if (!buildId || !sourceCommit || !artifactDigest) {
      throw new Error('recovery_installation_build_identity_unavailable');
    }
    return recoveryRootInstallationReportV1Schema.parse({
      schema: 'RecoveryRootInstallationReportV1',
      version: 1,
      readerId: 'enclave-boot-manifest-verifier',
      buildId,
      installedRootEpoch: 1,
      installedRootDigest: TRUSTED_SIGNER_RECOVERY_ROOT_DIGEST,
      sourceCommit,
      artifactDigest,
    });
  }

  async verifyDstackEvidence(
    input: DstackNativeVerificationInputV1,
  ): Promise<DstackNativeVerificationResultV1> {
    return this.#dstackEvidenceAdapter
      ? this.#dstackEvidenceAdapter.verify(input)
      : unavailableResult();
  }

  private keysFromSignedKeyset(keyset: BootManifestKeyset): readonly PinnedBootManifestKey[] {
    return keyset.keys.map((key) => ({
      keyId: key.keyId,
      status: key.status,
      publicKey: createPublicKey(key.publicKeyPem),
    }));
  }

  private createKeySet(
    pinnedKeys: readonly PinnedBootManifestKey[],
  ): ReadonlyMap<string, PinnedBootManifestKey> {
    if (!Array.isArray(pinnedKeys) || pinnedKeys.length === 0) {
      throw new Error(bootManifestVerificationErrors.keySet);
    }
    const keysById = new Map<string, PinnedBootManifestKey>();
    const fingerprints = new Set<string>();
    for (const key of pinnedKeys) {
      if (
        !key ||
        !this.isKeyId(key.keyId) ||
        !this.isStatus(key.status) ||
        !key.publicKey ||
        !(key.publicKey instanceof KeyObject) ||
        key.publicKey.type !== 'public' ||
        key.publicKey.asymmetricKeyType !== 'ed25519' ||
        keysById.has(key.keyId)
      ) {
        throw new Error(bootManifestVerificationErrors.keySet);
      }
      const fingerprint = this.publicKeyFingerprint(key.publicKey);
      if (fingerprints.has(fingerprint)) throw new Error(bootManifestVerificationErrors.keySet);
      fingerprints.add(fingerprint);
      keysById.set(
        key.keyId,
        Object.freeze({ keyId: key.keyId, status: key.status, publicKey: key.publicKey }),
      );
    }
    return keysById;
  }

  private matchesRuntimeIdentity(
    manifest: BootManifest,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): boolean {
    if (!runtimeIdentity || typeof runtimeIdentity !== 'object') return false;
    const resourcePrefixes = runtimeIdentity.resourcePrefixes;
    if (!resourcePrefixes || typeof resourcePrefixes !== 'object') return false;

    return (
      manifest.orgId === runtimeIdentity.orgId &&
      manifest.deploymentId === runtimeIdentity.deploymentId &&
      manifest.awsAccountId === runtimeIdentity.awsAccountId &&
      manifest.awsRegion === runtimeIdentity.awsRegion &&
      manifest.kmsKeyArn === runtimeIdentity.kmsKeyArn &&
      manifest.storageKeyArn === runtimeIdentity.storageKeyArn &&
      manifest.resourcePrefixes.sealedBlobsS3 === resourcePrefixes.sealedBlobsS3 &&
      manifest.resourcePrefixes.rawPayloadsS3 === resourcePrefixes.rawPayloadsS3 &&
      manifest.resourcePrefixes.processedOutputsS3 === resourcePrefixes.processedOutputsS3 &&
      manifest.resourcePrefixes.tenantSsm === resourcePrefixes.tenantSsm &&
      manifest.sourceSha === runtimeIdentity.sourceSha &&
      manifest.eifDigest === runtimeIdentity.eifDigest &&
      manifest.configurationGeneration === runtimeIdentity.configurationGeneration &&
      this.matchesControlPlaneIdentity(
        manifest.controlPlaneIdentity,
        runtimeIdentity.controlPlaneIdentity,
      )
    );
  }

  private assertProviderPolicyPrerequisites(manifest: BootManifest): void {
    if (manifest.providerInferenceTrustPolicy === undefined) return;
    if (
      manifest.inferenceTrustPolicy !== undefined ||
      manifest.inferenceAttestation !== undefined ||
      manifest.activePolicyBootTrust === undefined ||
      manifest.verifiedReleaseIdentity === undefined ||
      manifest.generationHighWaterRuntimeConfig === undefined
    ) {
      throw new Error(bootManifestVerificationErrors.invalid);
    }
  }

  private matchesControlPlaneIdentity(
    manifestIdentity: ControlPlaneIdentity | undefined,
    runtimeIdentity: ControlPlaneIdentity | undefined,
  ): boolean {
    if (manifestIdentity !== undefined && runtimeIdentity === undefined) return false;
    if (runtimeIdentity === undefined) return true;
    if (manifestIdentity === undefined) return false;
    return (
      manifestIdentity.origin === runtimeIdentity.origin &&
      manifestIdentity.tlsSpkiSha256.length === runtimeIdentity.tlsSpkiSha256.length &&
      manifestIdentity.tlsSpkiSha256.every(
        (pin, index) => pin === runtimeIdentity.tlsSpkiSha256[index],
      )
    );
  }

  private freezeOwnedManifest(manifest: BootManifest): VerifiedBootManifest {
    const secretReferences = manifest.secretReferences.map((reference) =>
      Object.freeze({ ...reference }),
    );
    const oauthProviders = Object.freeze(
      (manifest.oauthProviders ?? []).map((provider) =>
        Object.freeze({
          ...provider,
          allowedHosts: Object.freeze([...provider.allowedHosts]),
          ...(provider.jiraWebhookPilotOrgIds
            ? { jiraWebhookPilotOrgIds: Object.freeze([...provider.jiraWebhookPilotOrgIds]) }
            : {}),
          ...(provider.jiraWebhookClaimPolicy
            ? { jiraWebhookClaimPolicy: Object.freeze({ ...provider.jiraWebhookClaimPolicy }) }
            : {}),
        }),
      ),
    );
    const controlPlaneIdentity: FrozenControlPlaneIdentity | undefined =
      manifest.controlPlaneIdentity
        ? Object.freeze({
            ...manifest.controlPlaneIdentity,
            tlsSpkiSha256: Object.freeze([...manifest.controlPlaneIdentity.tlsSpkiSha256]),
          })
        : undefined;
    const inferenceTrustPolicy: FrozenInferenceTrustPolicy | undefined =
      manifest.inferenceTrustPolicy === undefined
        ? undefined
        : Object.freeze({
            ...manifest.inferenceTrustPolicy,
            redirectOrigins: Object.freeze([...manifest.inferenceTrustPolicy.redirectOrigins]),
            tlsSpkiSha256: Object.freeze([...manifest.inferenceTrustPolicy.tlsSpkiSha256]),
            quoteRootDigests: Object.freeze([...manifest.inferenceTrustPolicy.quoteRootDigests]),
            workloadMeasurements: Object.freeze([
              ...manifest.inferenceTrustPolicy.workloadMeasurements,
            ]),
            attestationKeys: Object.freeze(
              manifest.inferenceTrustPolicy.attestationKeys.map((key) => Object.freeze({ ...key })),
            ),
            receiptKeys: Object.freeze(
              manifest.inferenceTrustPolicy.receiptKeys.map((key) => Object.freeze({ ...key })),
            ),
            permittedModels: Object.freeze(
              manifest.inferenceTrustPolicy.permittedModels.map((model) =>
                Object.freeze({ ...model }),
              ),
            ),
            roleModels: Object.freeze({
              embed: Object.freeze({ ...manifest.inferenceTrustPolicy.roleModels.embed }),
              generate: Object.freeze({ ...manifest.inferenceTrustPolicy.roleModels.generate }),
              judge: Object.freeze({ ...manifest.inferenceTrustPolicy.roleModels.judge }),
              critique: Object.freeze({ ...manifest.inferenceTrustPolicy.roleModels.critique }),
            }),
          });
    const inferenceAttestation = manifest.inferenceAttestation
      ? Object.freeze({
          ...manifest.inferenceAttestation,
          modelAllowlist: Object.freeze([...manifest.inferenceAttestation.modelAllowlist]),
        })
      : undefined;
    const providerInferenceTrustPolicy = manifest.providerInferenceTrustPolicy
      ? this.deepFreeze(manifest.providerInferenceTrustPolicy)
      : undefined;
    const verifiedReleaseIdentity = manifest.verifiedReleaseIdentity
      ? Object.freeze({ ...manifest.verifiedReleaseIdentity })
      : undefined;
    const activePolicyBootTrust = manifest.activePolicyBootTrust
      ? Object.freeze({
          ...manifest.activePolicyBootTrust,
          authority: Object.freeze({ ...manifest.activePolicyBootTrust.authority }),
          carrierSigner: Object.freeze({ ...manifest.activePolicyBootTrust.carrierSigner }),
        })
      : undefined;
    const activePolicyCarrier = manifest.activePolicyCarrier
      ? Object.freeze({
          ...manifest.activePolicyCarrier,
          payload: Object.freeze({
            ...manifest.activePolicyCarrier.payload,
            activePolicy: Object.freeze({ ...manifest.activePolicyCarrier.payload.activePolicy }),
            authorizationEnvelope: Object.freeze({
              ...manifest.activePolicyCarrier.payload.authorizationEnvelope,
            }),
            generationContext: Object.freeze({
              ...manifest.activePolicyCarrier.payload.generationContext,
            }),
            protectedPolicyReference: Object.freeze({
              ...manifest.activePolicyCarrier.payload.protectedPolicyReference,
            }),
          }),
        })
      : undefined;
    return Object.freeze({
      ...manifest,
      resourcePrefixes: Object.freeze({ ...manifest.resourcePrefixes }),
      secretReferences: Object.freeze(secretReferences),
      oauthProviders,
      ...(controlPlaneIdentity ? { controlPlaneIdentity } : {}),
      ...(inferenceTrustPolicy ? { inferenceTrustPolicy } : {}),
      ...(inferenceAttestation ? { inferenceAttestation } : {}),
      ...(providerInferenceTrustPolicy ? { providerInferenceTrustPolicy } : {}),
      ...(verifiedReleaseIdentity ? { verifiedReleaseIdentity } : {}),
      ...(activePolicyBootTrust ? { activePolicyBootTrust } : {}),
      ...(activePolicyCarrier ? { activePolicyCarrier } : {}),
    });
  }

  private isKeyId(value: unknown): value is string {
    return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
  }

  private isStatus(value: unknown): value is PinnedBootManifestKeyStatus {
    return (
      value === 'active' ||
      value === 'verification-only' ||
      value === 'disabled' ||
      value === 'revoked'
    );
  }

  private publicKeyFingerprint(publicKey: KeyObject): string {
    return createHash('sha256')
      .update(publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
  }

  private deepFreeze<T>(value: T): DeepReadonly<T> {
    if (value && typeof value === 'object') {
      Object.freeze(value);
      for (const child of Object.values(value as Record<string, unknown>)) this.deepFreeze(child);
    }
    return value as DeepReadonly<T>;
  }
}
