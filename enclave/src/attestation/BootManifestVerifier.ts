import { createHash, createPublicKey, KeyObject, verify } from 'node:crypto';
import {
  signedBootManifestSchema,
  type BootManifest,
  type BootManifestResourcePrefixes,
  type BootManifestKeyset,
  type SignedBootManifestKeyset,
  type ControlPlaneIdentity,
} from '@folklore/contracts/enclave-attestation';
import { encodeBootManifest, verifySignedBootManifestKeyset } from '@folklore/nitro-attestation';
import {
  BOOT_MANIFEST_ROOT_KEY_ID,
  BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
  assertApprovedBootManifestRoot,
} from './boot-manifest-root.js';

export type PinnedBootManifestKeyStatus = 'active' | 'verification-only' | 'disabled' | 'revoked';

export interface PinnedBootManifestKey {
  keyId: string;
  status: PinnedBootManifestKeyStatus;
  publicKey: KeyObject;
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

export type VerifiedBootManifest = Readonly<
  Omit<
    BootManifest,
    'resourcePrefixes' | 'secretReferences' | 'oauthProviders' | 'controlPlaneIdentity'
  >
> & {
  readonly resourcePrefixes: Readonly<BootManifestResourcePrefixes>;
  readonly secretReferences: readonly Readonly<BootManifest['secretReferences'][number]>[];
  readonly oauthProviders: readonly Readonly<
    Omit<BootManifest['oauthProviders'][number], 'allowedHosts'> & {
      readonly allowedHosts: readonly string[];
    }
  >[];
  readonly controlPlaneIdentity?: FrozenControlPlaneIdentity;
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

  constructor(
    pinnedKeys:
      | readonly PinnedBootManifestKey[]
      | { signedKeyset: SignedBootManifestKeyset; rootKeyId?: string; rootPublicKeyPem?: string },
  ) {
    if (Array.isArray(pinnedKeys)) throw new Error(bootManifestVerificationErrors.keySet);
    if (!pinnedKeys || typeof pinnedKeys !== 'object' || !('signedKeyset' in pinnedKeys)) {
      throw new Error(bootManifestVerificationErrors.keySet);
    }
    const config = pinnedKeys as {
      signedKeyset: SignedBootManifestKeyset;
      rootKeyId?: string;
      rootPublicKeyPem?: string;
    };
    assertApprovedBootManifestRoot();
    this.#keysById = this.createKeySet(
      this.keysFromSignedKeyset(config.signedKeyset, config.rootKeyId, config.rootPublicKeyPem),
    );
  }

  verify(input: unknown, runtimeIdentity: BootManifestRuntimeIdentity): VerifiedBootManifest {
    const parsed = signedBootManifestSchema.safeParse(input);
    if (!parsed.success) throw new Error(bootManifestVerificationErrors.invalid);

    const key = this.#keysById.get(parsed.data.manifest.signerKeyId);
    if (!key || (key.status !== 'active' && key.status !== 'verification-only')) {
      throw new Error(bootManifestVerificationErrors.signer);
    }

    const isValid = verify(
      null,
      encodeBootManifest(parsed.data.manifest),
      key.publicKey,
      Buffer.from(parsed.data.signature, 'base64'),
    );
    if (!isValid) throw new Error(bootManifestVerificationErrors.signature);
    if (!this.matchesRuntimeIdentity(parsed.data.manifest, runtimeIdentity)) {
      throw new Error(bootManifestVerificationErrors.identity);
    }
    return this.freezeOwnedManifest(parsed.data.manifest);
  }

  private keysFromSignedKeyset(
    signedKeyset: SignedBootManifestKeyset,
    rootKeyId = BOOT_MANIFEST_ROOT_KEY_ID,
    rootPublicKeyPem = BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM,
  ): readonly PinnedBootManifestKey[] {
    const keyset = verifySignedBootManifestKeyset(signedKeyset, rootKeyId, rootPublicKeyPem);
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
    return Object.freeze({
      ...manifest,
      resourcePrefixes: Object.freeze({ ...manifest.resourcePrefixes }),
      secretReferences: Object.freeze(secretReferences),
      oauthProviders,
      ...(controlPlaneIdentity ? { controlPlaneIdentity } : {}),
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
}
