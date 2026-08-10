import {
  bootManifestSchema,
  bootManifestUserDataSchema,
  enclaveHealthRecordSchema,
  type BootManifest,
  type BootManifestUserData,
  type EnclaveHealthRecord,
  runtimeAttestationKeyBundleSchema,
  type RuntimeAttestationKeyBundle,
} from '@folklore/contracts/enclave-attestation';
import { encode } from 'cborg';
import { createHash } from 'node:crypto';

const CONFIGURATION_GENERATION_MAX = 2_147_483_647;
const NITRO_USER_DATA_MAX_BYTES = 512;

function encodeSecretReference(reference: BootManifest['secretReferences'][number]): unknown[] {
  if (reference.store === 'secrets-manager') {
    return [reference.store, reference.id, reference.arn, reference.versionId];
  }
  return [reference.store, reference.id, reference.path, reference.version];
}

function encodeOAuthProvider(provider: BootManifest['oauthProviders'][number]): unknown[] {
  return [
    provider.enabled,
    provider.kind,
    provider.tokenEndpoint,
    provider.identityEndpoint,
    provider.githubInstallationEndpoint,
    provider.secretReferenceId,
    [...provider.allowedHosts],
  ];
}

export function encodeBootManifest(input: BootManifest): Uint8Array {
  const manifest = bootManifestSchema.parse(input);
  const fields: unknown[] = [
    'folklore.boot-manifest.v1',
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
    manifest.secretReferences.map(encodeSecretReference),
    manifest.oauthProviders.map(encodeOAuthProvider),
  ];
  if (manifest.controlPlaneIdentity !== undefined) {
    fields.push([
      manifest.controlPlaneIdentity.origin,
      [...manifest.controlPlaneIdentity.tlsSpkiSha256],
    ]);
  }
  // A field the manifest carries but the signature does not cover is parent-writable: the parent
  // holds the signed manifest and can rewrite any unsigned byte in it and still verify.
  if (manifest.recoveryPubkey !== undefined) fields.push(manifest.recoveryPubkey);
  // The tagged tuple preserves the established recovery-only encoding while keeping this optional
  // string distinct from an optional recovery key in the canonical signed payload.
  if (manifest.assignmentManifestPublicKeySpki !== undefined) {
    fields.push(['assignment-manifest-public-key-spki', manifest.assignmentManifestPublicKeySpki]);
  }
  return encode(fields);
}

export function hashBootManifest(manifest: BootManifest): string {
  return createHash('sha256').update(encodeBootManifest(manifest)).digest('hex');
}

export function hashNitroDocument(document: Uint8Array): string {
  return createHash('sha256').update(document).digest('hex');
}

export function encodeRuntimeAttestationKeyBundle(input: RuntimeAttestationKeyBundle): Uint8Array {
  const bundle = runtimeAttestationKeyBundleSchema.parse(input);
  return encode([
    'folklore.runtime-attestation-key-bundle.v1',
    bundle.signingPublicKey,
    bundle.responseEncryptionPublicKey,
    bundle.ingestPublicKey,
  ]);
}

export function hashRuntimeAttestationKeyBundle(input: RuntimeAttestationKeyBundle): string {
  return createHash('sha256').update(encodeRuntimeAttestationKeyBundle(input)).digest('hex');
}

export function deriveAttestationUserData(manifest: BootManifest): BootManifestUserData {
  return bootManifestUserDataSchema.parse({
    version: 1,
    manifestHash: hashBootManifest(manifest),
    configurationGeneration: manifest.configurationGeneration,
    orgId: manifest.orgId,
    deploymentId: manifest.deploymentId,
    sourceSha: manifest.sourceSha,
    eifDigest: manifest.eifDigest,
    kmsKeyArn: manifest.kmsKeyArn,
    storageKeyArn: manifest.storageKeyArn,
  });
}

export function encodeAttestationUserData(
  input: BootManifestUserData,
  runtimeKeyBundleHash?: string,
): Uint8Array {
  const userData = bootManifestUserDataSchema.parse(input);
  const fields: unknown[] = [
    'folklore.nitro-user-data.v1',
    userData.version,
    userData.manifestHash,
    userData.configurationGeneration,
    userData.orgId,
    userData.deploymentId,
    userData.sourceSha,
    userData.eifDigest,
    userData.kmsKeyArn,
    userData.storageKeyArn,
  ];
  if (runtimeKeyBundleHash !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(runtimeKeyBundleHash))
      throw new TypeError('invalid key bundle hash');
    fields.push(runtimeKeyBundleHash);
  }
  return enforceAttestationUserDataSize(encode(fields));
}

export function enforceAttestationUserDataSize(encoded: Uint8Array): Uint8Array {
  if (encoded.byteLength > NITRO_USER_DATA_MAX_BYTES) {
    throw new TypeError('invalid attestation user data');
  }
  return encoded;
}

export interface RuntimeHealthSignaturePayload {
  nonce: Uint8Array;
  documentHash: string;
  manifestHash: string;
  configurationGeneration: number;
  record: EnclaveHealthRecord;
}

export function encodeRuntimeHealthSignaturePayload(
  input: RuntimeHealthSignaturePayload,
): Uint8Array {
  const record = enclaveHealthRecordSchema.parse(input.record);
  if (input.nonce.byteLength !== 32 || !/^[0-9a-f]{64}$/.test(input.documentHash)) {
    throw new TypeError('invalid runtime health binding');
  }
  if (!/^[0-9a-f]{64}$/.test(input.manifestHash)) {
    throw new TypeError('invalid runtime health binding');
  }
  if (
    !Number.isInteger(input.configurationGeneration) ||
    input.configurationGeneration < 1 ||
    input.configurationGeneration > CONFIGURATION_GENERATION_MAX
  ) {
    throw new TypeError('invalid runtime health binding');
  }
  return encode([
    'folklore.runtime-health.v1',
    input.nonce,
    input.documentHash,
    input.manifestHash,
    input.configurationGeneration,
    record.version,
    record.observedAt,
    record.status,
    record.tenantAssigned,
    record.bootManifestVerified,
    record.kmsUnsealed,
    record.tenantApiReady,
  ]);
}
