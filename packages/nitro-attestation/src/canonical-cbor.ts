import {
  bootManifestSchema,
  dormantBootManifestV2CarrierManifestSchema,
  bootManifestUserDataSchema,
  enclaveHealthRecordSchema,
  type BootManifest,
  type DormantBootManifestV2CarrierManifest,
  type BootManifestUserData,
  type EnclaveHealthRecord,
  runtimeAttestationKeyBundleSchema,
  poolRuntimeAttestationUserDataSchema,
  type RuntimeAttestationKeyBundle,
  type PoolRuntimeAttestationUserData,
} from '@folklore/contracts/enclave-attestation';
import {
  ACTIVE_INFERENCE_TRUST_POLICY_V2_CANONICAL_DOMAIN,
  activeInferenceTrustPolicyV2Schema,
  durableGenerationHighWaterCheckpointSchema,
  gatewayEvidenceEnvelopeSchema,
} from '@folklore/contracts';
import type {
  ActivePolicyAuthorizationEnvelopeV1,
  ActiveInferenceTrustPolicyV2,
  DurableGenerationHighWaterCheckpointV1,
  GatewayEvidenceEnvelopeV1,
  InferenceTrustPolicyV1,
  InferenceTrustPolicyV2,
} from '@folklore/contracts';
import { encode, rfc8949EncodeOptions } from 'cborg';
import { createHash } from 'node:crypto';
import { canonicalJson, type AssignmentManifestV3Payload } from '@folklore/contracts';

const CONFIGURATION_GENERATION_MAX = 2_147_483_647;
const NITRO_USER_DATA_MAX_BYTES = 512;
const DURABLE_GENERATION_HIGH_WATER_CHECKPOINT_DOMAIN =
  'folklore.durable-generation-high-water-checkpoint.v1';
const GATEWAY_EVIDENCE_ENVELOPE_DOMAIN = 'folklore.aci-gateway-evidence.v1';

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
    provider.jiraWebhookMode ?? 'off',
    provider.jiraWebhookPilotOrgIds === undefined ? null : [...provider.jiraWebhookPilotOrgIds],
    provider.jiraWebhookClaimPolicy === undefined
      ? null
      : [
          provider.jiraWebhookClaimPolicy.issuer ?? null,
          provider.jiraWebhookClaimPolicy.audience ?? null,
          provider.jiraWebhookClaimPolicy.tenantClaimName ?? null,
          provider.jiraWebhookClaimPolicy.qshClaimName ?? null,
          provider.jiraWebhookClaimPolicy.matchedWebhookIdsClaimName ?? null,
          provider.jiraWebhookClaimPolicy.maxLifetimeSeconds ?? null,
        ],
  ];
}

function encodeRuntimeDatabase(config: NonNullable<BootManifest['runtimeDatabase']>): unknown[] {
  return [
    config.version,
    [config.endpoint.host, config.endpoint.port],
    config.database,
    [
      config.envelope.parameterPath,
      config.envelope.parameterVersion,
      config.envelope.envelopeSha256,
      config.envelope.runtimeEnvelopeKeyArn,
      config.envelope.poolDeploymentId,
      config.envelope.dbResourceId,
      config.envelope.managementSecretArn,
      config.envelope.managementSecretVersionId,
      config.envelope.username,
    ],
  ];
}

function encodeInferenceAttestation(
  config: NonNullable<BootManifest['inferenceAttestation']>,
): unknown[] {
  return [
    config.endpoint,
    config.expectedHost,
    config.workloadId,
    config.keysetDigest,
    config.embedModel,
    config.generateModel,
    config.critiqueModel,
    config.judgeModel,
    config.embedDim,
    config.generateMaxTokens,
    [...config.modelAllowlist],
  ];
}

function encodeActivePolicyBootTrust(
  trust: NonNullable<BootManifest['activePolicyBootTrust']>,
): unknown[] {
  return [
    trust.schema,
    trust.releaseId,
    trust.pcr0,
    trust.bootRootDigest,
    [
      trust.authority.keyArn,
      trust.authority.keyId,
      trust.authority.publicKeySpkiSha256,
      trust.authority.epoch,
    ],
    [
      trust.carrierSigner.schema,
      trust.carrierSigner.version,
      trust.carrierSigner.keyArn,
      trust.carrierSigner.keyId,
      trust.carrierSigner.publicKeySpkiSha256,
      trust.carrierSigner.epoch,
    ],
  ];
}

function encodeVerifiedReleaseIdentity(
  identity: NonNullable<BootManifest['verifiedReleaseIdentity']>,
): unknown[] {
  return [identity.releaseId, identity.pcr0, identity.bootRootDigest];
}

function encodeInferenceTrustPolicy(
  policy: InferenceTrustPolicyV1 | InferenceTrustPolicyV2,
): unknown[] {
  if (policy.version === 1) {
    return [
      'inference-trust-policy-v1',
      policy.version,
      policy.generation,
      policy.origin,
      policy.route,
      [...policy.redirectOrigins],
      [...policy.tlsSpkiSha256],
      policy.workloadId,
      [...policy.quoteRootDigests],
      [...policy.workloadMeasurements],
      policy.attestationKeys.map((key) => [key.keyId, key.algorithm, key.publicKey]),
      policy.receiptKeys.map((key) => [key.keyId, key.algorithm, key.publicKey]),
      policy.permittedModels.map((model) => [model.model, model.revision]),
      [
        [policy.roleModels.embed.model, policy.roleModels.embed.revision],
        [policy.roleModels.generate.model, policy.roleModels.generate.revision],
        [policy.roleModels.judge.model, policy.roleModels.judge.revision],
        [policy.roleModels.critique.model, policy.roleModels.critique.revision],
      ],
    ];
  }
  return [
    'inference-trust-policy-v2',
    policy.version,
    policy.generation,
    policy.origin,
    policy.route,
    policy.channelPolicy.acceptedBindings.map((binding) => {
      if (binding.type === 'e2ee_public_key_sha256') {
        return [binding.type, [...binding.domains], [...binding.algorithms]];
      }
      return [binding.type, [...binding.domains]];
    }),
    [
      [...policy.evidence.teeTypes],
      [...policy.evidence.quoteRootDigests],
      [...policy.evidence.tcbStatuses],
      [...policy.evidence.runtimeMeasurements],
      [...policy.evidence.runtimeRtmrs],
      [...policy.evidence.runtimeIdentities],
      [...policy.evidence.dstackAppIdentities],
      [...policy.evidence.measuredComposeDigests],
      [...policy.evidence.imageDigests],
      [...policy.evidence.dstackKmsRoots],
      ...(policy.evidence.profile === undefined
        ? []
        : [['public-aci-profile-v1', policy.evidence.profile]]),
    ],
    [
      policy.sourceProvenance.repositories.map((repository) => [
        repository.repoUrl,
        [...repository.commits],
      ]),
      [...policy.sourceProvenance.imageDigests],
    ],
    [...policy.requiredSessionClaims],
    [...policy.permittedClaimSources],
    policy.permittedModels.map((model) => [model.model, model.revision]),
    [
      [policy.roleModels.embed.model, policy.roleModels.embed.revision],
      [policy.roleModels.generate.model, policy.roleModels.generate.revision],
      [policy.roleModels.judge.model, policy.roleModels.judge.revision],
      [policy.roleModels.critique.model, policy.roleModels.critique.revision],
    ],
    policy.maxKeysetLifetimeSeconds,
    policy.maxSessionLifetimeSeconds,
    policy.clockSkewSeconds,
  ];
}

function encodeActiveInferenceRoleBinding(
  binding: ActiveInferenceTrustPolicyV2['roles']['embed'],
): unknown[] {
  return [
    binding.orgId,
    binding.deploymentId,
    binding.tenantContextDigest,
    binding.role,
    binding.sessionId,
    binding.model,
    binding.modelRevision,
    binding.modelArtifactDigest,
    binding.upstreamIdentityDigest,
    binding.workloadKeysetDigest,
    binding.channelKeyDigest,
    [...binding.channelPins],
    binding.routeIdentityDigest,
    [...binding.requiredSessionClaims],
    [...binding.permittedClaimSources],
    [
      binding.capabilities.embeddingDimension,
      binding.capabilities.maxOutputTokens,
      binding.capabilities.temperature,
      binding.capabilities.structuredOutput,
    ],
    binding.establishedAt,
    binding.expiresAt,
  ];
}

function encodeGatewayEvidenceRoleBinding(
  binding: GatewayEvidenceEnvelopeV1['roleBindings'][number],
): unknown[] {
  return [
    binding.role,
    binding.sessionId,
    binding.model,
    binding.modelRevision,
    binding.modelArtifactDigest,
    binding.channelKeyDigest,
    binding.expiresAt,
  ];
}

function encodeCommissioningProvenance(
  provenance: NonNullable<GatewayEvidenceEnvelopeV1['commissioningProvenance']>,
): unknown[] {
  return [
    provenance.protectedSourceCommit,
    provenance.eifArtifactPath,
    provenance.eifDigest,
    provenance.pcr0,
    provenance.bootRootDigest,
    provenance.deploymentId,
    provenance.runtimeIdentityDigest,
    provenance.recipientKmsReceiptDigest,
    provenance.assignmentAcknowledgmentDigest,
    provenance.routeProofDigest,
    provenance.admissionProofDigest,
    provenance.queueChecksDigest,
    provenance.dlqChecksDigest,
    provenance.aciReportSignatureDigest,
    provenance.releaseProvenanceDigest,
    provenance.finalCommitMarker,
  ];
}

export function encodeActiveInferenceTrustPolicyV2(
  input: ActiveInferenceTrustPolicyV2,
): Uint8Array {
  return encodeActiveInferenceTrustPolicyV2Fields(input, true);
}

export function encodeActiveInferenceTrustPolicyV2AuthorizationInput(
  input: ActiveInferenceTrustPolicyV2,
): Uint8Array {
  return encodeActiveInferenceTrustPolicyV2Fields(input, false);
}

function encodeActiveInferenceTrustPolicyV2Fields(
  input: ActiveInferenceTrustPolicyV2,
  includeAuthorizationEnvelopeDigest: boolean,
): Uint8Array {
  const policy = activeInferenceTrustPolicyV2Schema.parse(input);
  const fields: unknown[] = [
    ACTIVE_INFERENCE_TRUST_POLICY_V2_CANONICAL_DOMAIN,
    policy.schema,
    policy.canonicalDomain,
    policy.version,
    policy.orgId,
    policy.deploymentId,
    policy.policyGeneration,
    policy.activationGeneration,
    policy.configurationGeneration,
    policy.policyAuthorityKeyId,
  ];
  if (includeAuthorizationEnvelopeDigest) fields.push(policy.authorizationEnvelopeDigest);
  fields.push(
    [
      policy.route.origin,
      policy.route.path,
      policy.route.method,
      [...policy.route.redirectOrigins],
    ],
    [
      [...policy.channel.tlsSpkiSha256],
      policy.channel.e2eeKeyId,
      policy.channel.channelKeyDigest,
      policy.channel.exporterLabel,
    ],
    [
      policy.verifier.dstackSourceCommit,
      policy.verifier.dstackArchiveSha256,
      policy.verifier.verifierSourceCommit,
      policy.verifier.verifierArchiveSha256,
      [...policy.verifier.quoteRootDigests],
      [...policy.verifier.acceptedTcbStatuses],
      policy.verifier.runtimeIdentityDigest,
      policy.verifier.workloadIdentityDigest,
      policy.verifier.workloadArtifactDigest,
      policy.verifier.routeIdentityDigest,
    ],
    policy.permittedModels.map((model) => [
      model.model,
      model.modelRevision,
      model.modelArtifactDigest,
    ]),
    [
      encodeActiveInferenceRoleBinding(policy.roles.embed),
      encodeActiveInferenceRoleBinding(policy.roles.generate),
      encodeActiveInferenceRoleBinding(policy.roles.critique),
      encodeActiveInferenceRoleBinding(policy.roles.judge),
    ],
    [
      policy.proof.version,
      policy.proof.issuerWorkloadId,
      policy.proof.pinnedTrustRootDigest,
      policy.proof.proofKeysetDigest,
      policy.proof.maximumLifetimeMs,
    ],
    [
      policy.minimumHighWater.policyGeneration,
      policy.minimumHighWater.activationGeneration,
      policy.minimumHighWater.keysetEpoch,
      policy.minimumHighWater.keysetDigest,
    ],
    [
      policy.lifetime.snapshotExpiresAt,
      policy.lifetime.maximumSessionLifetimeMs,
      policy.lifetime.maximumKeysetLifetimeMs,
      policy.lifetime.admissionLeaseLifetimeMs,
      policy.lifetime.clockSkewMs,
    ],
    [
      policy.sourceProvenance.protectedSourceCommit,
      policy.sourceProvenance.sourceArchiveSha256,
      policy.sourceProvenance.releaseId,
      policy.sourceProvenance.eifDigest,
      policy.sourceProvenance.pcr0,
      policy.sourceProvenance.releaseProvenanceDigest,
    ],
    [
      policy.rollbackFloor.minimumPolicyGeneration,
      policy.rollbackFloor.minimumActivationGeneration,
      policy.rollbackFloor.priorPolicyDigest,
    ],
  );
  return encode(fields);
}

export function encodeActivePolicyAuthorizationEnvelopeV1(
  input: Omit<ActivePolicyAuthorizationEnvelopeV1, 'signature'>,
): Uint8Array {
  const fields: unknown[] = [
    ACTIVE_INFERENCE_TRUST_POLICY_V2_CANONICAL_DOMAIN,
    input.schema,
    input.orgId,
    input.deploymentId,
    input.policyDigest,
    input.protectedPolicyReference,
    input.policyGeneration,
    input.activationGeneration,
    input.configurationGeneration,
    [input.keysetHighWater.epoch, input.keysetHighWater.digest],
    input.signerPurpose,
    input.signerKeyId,
    input.signatureAlgorithm,
    input.policySignature,
  ];

  if (
    input.authorityKmsKeyArn === undefined &&
    input.authorityPublicKeySpkiSha256 === undefined &&
    input.authorityEpoch === undefined
  ) {
    return encode(fields);
  }
  if (
    input.authorityKmsKeyArn === undefined ||
    input.authorityPublicKeySpkiSha256 === undefined ||
    input.authorityEpoch === undefined
  ) {
    throw new Error('active_policy_authority_identity_incomplete');
  }
  fields.splice(
    10,
    0,
    input.authorityKmsKeyArn,
    input.authorityPublicKeySpkiSha256,
    input.authorityEpoch,
  );
  return encode(fields);
}

export function digestActivePolicyAuthorizationEnvelopeV1(
  input: Omit<ActivePolicyAuthorizationEnvelopeV1, 'signature'>,
): string {
  return createHash('sha256')
    .update(encodeActivePolicyAuthorizationEnvelopeV1(input))
    .digest('hex');
}

export function encodeDurableGenerationHighWaterCheckpoint(
  input: DurableGenerationHighWaterCheckpointV1,
): Uint8Array {
  const checkpoint = durableGenerationHighWaterCheckpointSchema.parse(input);
  return encode([
    DURABLE_GENERATION_HIGH_WATER_CHECKPOINT_DOMAIN,
    checkpoint.checkpointVersion,
    checkpoint.orgId,
    checkpoint.deploymentId,
    checkpoint.policyGeneration,
    checkpoint.activationGeneration,
    [checkpoint.keysetHighWater.epoch, checkpoint.keysetHighWater.digest],
    checkpoint.policyDigest,
    checkpoint.releaseId,
    checkpoint.protectedSourceCommit,
    checkpoint.eifDigest,
    checkpoint.signerKeyId,
    checkpoint.previousCheckpointDigest,
    checkpoint.issuedAt,
    checkpoint.checkpointDigest,
    checkpoint.signature,
  ]);
}

export function encodeGatewayEvidenceEnvelope(input: GatewayEvidenceEnvelopeV1): Uint8Array {
  const evidence = gatewayEvidenceEnvelopeSchema.parse(input);
  return encode([
    GATEWAY_EVIDENCE_ENVELOPE_DOMAIN,
    evidence.evidenceId,
    evidence.orgId,
    evidence.deploymentId,
    evidence.tenantContextDigest,
    evidence.eifDigest,
    evidence.pcr0,
    evidence.bootRootDigest,
    evidence.gatewayBuildDigest,
    evidence.verifierSourceCommit,
    evidence.verifierArchiveSha256,
    evidence.dcapQvlVersion,
    evidence.releaseProvenanceDigest,
    evidence.policyDigest,
    evidence.policyGeneration,
    evidence.activationGeneration,
    [evidence.keysetHighWater.epoch, evidence.keysetHighWater.digest],
    evidence.routeIdentity,
    evidence.keysetDigest,
    evidence.roleBindings.map(encodeGatewayEvidenceRoleBinding),
    [
      evidence.admission.decision,
      evidence.admission.scope,
      evidence.admission.assignmentDigest,
      evidence.admission.leaseExpiry,
    ],
    [
      evidence.trustedTime.checkpointDigest,
      evidence.trustedTime.bootEpoch,
      evidence.trustedTime.sampledAt,
    ],
    evidence.exchange === null
      ? null
      : [evidence.exchange.role, evidence.exchange.servedAt, evidence.exchange.result],
    evidence.commissioningProvenance === null
      ? null
      : encodeCommissioningProvenance(evidence.commissioningProvenance),
    evidence.failureCode,
    evidence.createdAt,
    evidence.signerKeyId,
    evidence.signature,
  ]);
}

export function encodeBootManifest(input: BootManifest): Uint8Array {
  const manifest = bootManifestSchema.parse(input);
  return encodeManifestFields('folklore.boot-manifest.v2', manifest);
}

export function encodeDormantBootManifestV2CarrierManifest(
  input: DormantBootManifestV2CarrierManifest,
): Uint8Array {
  const manifest = dormantBootManifestV2CarrierManifestSchema.parse(input);
  const { inferenceAttestation: _legacyInferenceAttestation, ...carrierManifest } =
    manifest as typeof manifest & {
      inferenceAttestation?: unknown;
    };
  return encodeManifestFields('folklore.dormant-boot-manifest-v2-carrier.v1', carrierManifest);
}

function encodeManifestFields(
  domain: string,
  manifest: BootManifest | DormantBootManifestV2CarrierManifest,
): Uint8Array {
  const fields: unknown[] = [
    domain,
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
      'control-plane-identity',
      [manifest.controlPlaneIdentity.origin, [...manifest.controlPlaneIdentity.tlsSpkiSha256]],
    ]);
  }
  if (manifest.runtimeDatabase !== undefined)
    fields.push(['runtime-database', encodeRuntimeDatabase(manifest.runtimeDatabase)]);
  if (manifest.inferenceAttestation !== undefined) {
    fields.push([
      'inference-attestation',
      encodeInferenceAttestation(manifest.inferenceAttestation),
    ]);
  }
  // A field the manifest carries but the signature does not cover is parent-writable: the parent
  // holds the signed manifest and can rewrite any unsigned byte in it and still verify. The
  // recovery key is the one that reaches all content if substituted (audit F2). Tagged optional
  // fields keep distinct semantic manifests distinct even when two optional values share a type.
  if (manifest.recoveryPubkey !== undefined)
    fields.push(['recovery-pubkey', manifest.recoveryPubkey]);
  // The tagged tuple preserves the established recovery-only encoding while keeping this optional
  // string distinct from an optional recovery key in the canonical signed payload.
  if (manifest.assignmentManifestPublicKeySpki !== undefined) {
    fields.push(['assignment-manifest-public-key-spki', manifest.assignmentManifestPublicKeySpki]);
  }
  if (manifest.activePolicyReference !== undefined) {
    fields.push([
      'active-policy-reference',
      [
        manifest.activePolicyReference.orgId,
        manifest.activePolicyReference.deploymentId,
        manifest.activePolicyReference.protectedPolicyReference,
        manifest.activePolicyReference.policyDigest,
        manifest.activePolicyReference.policyGeneration,
        manifest.activePolicyReference.activationGeneration,
        manifest.activePolicyReference.configurationGeneration,
        [
          manifest.activePolicyReference.keysetHighWater.epoch,
          manifest.activePolicyReference.keysetHighWater.digest,
        ],
      ],
    ]);
  }
  if (manifest.activePolicyBootTrust !== undefined) {
    fields.push([
      'active-policy-boot-trust',
      encodeActivePolicyBootTrust(manifest.activePolicyBootTrust),
    ]);
  }
  if (manifest.verifiedReleaseIdentity !== undefined) {
    fields.push([
      'verified-release-identity',
      encodeVerifiedReleaseIdentity(manifest.verifiedReleaseIdentity),
    ]);
  }
  if (manifest.inferenceTrustPolicy !== undefined) {
    fields.push(encodeInferenceTrustPolicy(manifest.inferenceTrustPolicy));
  }
  if (manifest.providerInferenceTrustPolicy !== undefined) {
    fields.push([
      'provider-inference-trust-policy.v1',
      encodeInferenceTrustPolicy(manifest.providerInferenceTrustPolicy),
    ]);
  }
  if (manifest.enclaveOutputKey !== undefined) {
    fields.push([
      'enclave-output-key',
      [
        manifest.enclaveOutputKey.keyId,
        manifest.enclaveOutputKey.publicKeySpki,
        manifest.enclaveOutputKey.privateKeySecretReferenceId,
        manifest.enclaveOutputKeyKmsKeyArn,
      ],
    ]);
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

export function encodePoolRuntimeAttestationUserData(
  input: PoolRuntimeAttestationUserData,
): Uint8Array {
  const userData = poolRuntimeAttestationUserDataSchema.parse(input);
  return enforceAttestationUserDataSize(
    encode([
      'folklore.pool-runtime-attestation.v1',
      userData.version,
      userData.poolDeploymentId,
      userData.assignmentGeneration,
      userData.assignmentDigest,
      [
        userData.runtimeDatabase.version,
        userData.runtimeDatabase.envelopeSha256,
        userData.runtimeDatabase.bindingSha256,
        userData.runtimeDatabase.parameterVersion,
        userData.runtimeDatabase.role,
        userData.runtimeDatabase.rls,
        userData.runtimeDatabase.apiHealth,
      ],
      userData.sessionPublicKeySha256,
    ]),
  );
}

export function encodePoolRuntimeHealthSignaturePayload(input: {
  nonce: Uint8Array;
  documentHash: string;
  userData: PoolRuntimeAttestationUserData;
  record: EnclaveHealthRecord;
}): Uint8Array {
  if (input.nonce.byteLength !== 32 || !/^[0-9a-f]{64}$/.test(input.documentHash)) {
    throw new TypeError('invalid pool runtime health binding');
  }
  const record = enclaveHealthRecordSchema.parse(input.record);
  return encode([
    'folklore.pool-runtime-health.v1',
    input.nonce,
    input.documentHash,
    encodePoolRuntimeAttestationUserData(input.userData),
    record.version,
    record.observedAt,
    record.status,
    record.tenantAssigned,
    record.bootManifestVerified,
    record.kmsUnsealed,
    record.tenantApiReady,
    record.runtimeDatabase
      ? [
          record.runtimeDatabase.version,
          record.runtimeDatabase.envelopeSha256,
          record.runtimeDatabase.bindingSha256,
          record.runtimeDatabase.parameterVersion,
          record.runtimeDatabase.role,
          record.runtimeDatabase.rls,
          record.runtimeDatabase.apiHealth,
        ]
      : null,
  ]);
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
  const fields: unknown[] = [
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
  ];
  if (record.runtimeDatabase) {
    fields.push([
      record.runtimeDatabase.version,
      record.runtimeDatabase.envelopeSha256,
      record.runtimeDatabase.bindingSha256,
      record.runtimeDatabase.parameterVersion,
      record.runtimeDatabase.role,
      record.runtimeDatabase.rls,
      record.runtimeDatabase.apiHealth,
    ]);
  }
  return encode(fields);
}

// PR2 canonical subject recipe (plan "Canonical subject and KMS message bytes"): a typed subject
// value is canonical-CBOR-encoded exactly once; the subject digest is SHA-256 of those bytes; the
// signature message is built from the domain tag and those exact bytes. Never double-encode
// already-canonical bytes and never hash an envelope wrapper.
export function canonicalCbor(value: unknown): Uint8Array {
  return encode(value, rfc8949EncodeOptions);
}

export function canonicalJsonDigest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function digestCanonicalCbor(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export interface BootManifestSubjectV3ScopeInput {
  manifestGeneration: number;
  orgId: string;
  deploymentId: string;
  environment: string;
  awsAccountId: string;
  awsRegion: string;
}

export function encodeBootManifestSubjectV3(input: {
  manifest: BootManifest;
  scope: BootManifestSubjectV3ScopeInput;
}): Uint8Array {
  const { signerKeyId: _signerOwned, ...unsignedManifest } = input.manifest;
  return canonicalCbor([
    'folklore.boot-manifest.v3',
    3,
    canonicalJsonDigest(unsignedManifest),
    input.scope.manifestGeneration,
    input.scope.orgId,
    input.scope.deploymentId,
    input.scope.environment,
    input.scope.awsAccountId,
    input.scope.awsRegion,
  ]);
}

export function encodeAssignmentManifestSubjectV3(input: {
  payload: AssignmentManifestV3Payload;
}): Uint8Array {
  return canonicalCbor([
    'folklore.assignment-manifest.v3',
    3,
    canonicalJsonDigest(input.payload),
    input.payload.generation,
    input.payload.orgId,
    input.payload.deploymentId,
    input.payload.poolId,
    input.payload.environment,
    input.payload.awsAccountId,
    input.payload.awsRegion,
  ]);
}

export function encodeDormantBootCarrierSubjectV1(input: {
  carrier: DormantBootManifestV2CarrierManifest;
  scope: {
    carrierGeneration: number;
    orgId: string;
    deploymentId: string;
    environment: string;
    awsAccountId: string;
    awsRegion: string;
  };
}): Uint8Array {
  const { signerKeyId: _signerOwned, ...unsignedCarrier } = input.carrier;
  return canonicalCbor([
    'folklore.dormant-boot-manifest-v3-carrier.v1',
    1,
    canonicalJsonDigest(unsignedCarrier),
    input.scope.carrierGeneration,
    input.scope.orgId,
    input.scope.deploymentId,
    input.scope.environment,
    input.scope.awsAccountId,
    input.scope.awsRegion,
  ]);
}
