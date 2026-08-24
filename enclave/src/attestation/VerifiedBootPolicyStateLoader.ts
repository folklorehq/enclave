import {
  digestSignedActivePolicyCarrierV1,
  encodeActivePolicyCarrierPayloadV1,
} from '@folklore/nitro-attestation';
import {
  assertVerifiedActivePolicyReferenceV1,
  mintVerifiedActivePolicyCarrierV1,
  mintVerifiedBootPolicyStateV1,
  type ActivePolicyCarrierVerifierPort,
  type VerifiedBootPolicyStateV1,
} from '@folklore/inference';
import type { BootManifest } from '@folklore/contracts/enclave-attestation';
import type { VerifiedBootManifest } from './BootManifestVerifier.js';
import {
  buildV4ExpectedGenerationContext,
  type BootBoundGenerationContext,
} from '../inference/BootStateActivePolicyReferenceVerifier.js';

// Verified active-policy state comes only from the signed boot manifest. No composition root may
// pass a policy object, reference URL, receipt metadata, environment variable, or assignment
// metadata as policy authority: the loader reads the signed carrier from the verified manifest,
// verifies it through the shared carrier verifier, and mints the opaque boot-state brand.
export interface VerifiedBootPolicyStateLoaderConfig {
  readonly verifiedManifest: VerifiedBootManifest;
  readonly carrierVerifier: ActivePolicyCarrierVerifierPort;
}

export function buildVerifiedBootGenerationContext(
  manifest: VerifiedBootManifest,
): BootBoundGenerationContext {
  const trust = manifest.activePolicyBootTrust;
  if (!trust) throw new Error('boot_manifest_active_policy_boot_trust_unavailable');
  const identity = manifest.verifiedReleaseIdentity;
  if (!identity) throw new Error('boot_manifest_verified_release_identity_unavailable');
  if (
    identity.releaseId !== trust.releaseId ||
    identity.pcr0 !== trust.pcr0 ||
    identity.bootRootDigest !== trust.bootRootDigest
  ) {
    throw new Error('boot_manifest_release_identity_mismatch');
  }
  return {
    configurationGeneration: manifest.configurationGeneration,
    releaseId: identity.releaseId,
    protectedSourceCommit: manifest.sourceSha,
    eifDigest: manifest.eifDigest,
    pcr0: identity.pcr0,
    bootRootDigest: identity.bootRootDigest,
  };
}

export class VerifiedBootPolicyStateLoader {
  constructor(private readonly config: VerifiedBootPolicyStateLoaderConfig) {}

  async loadVerifiedBootPolicyState(): Promise<VerifiedBootPolicyStateV1> {
    const carrier = this.carrierFromVerifiedManifest();
    const bootContext = buildVerifiedBootGenerationContext(this.config.verifiedManifest);
    const expectedContext = buildV4ExpectedGenerationContext({
      bootContext,
      carrierContext: carrier.payload.generationContext,
      tenantId: this.config.verifiedManifest.orgId,
      deploymentId: this.config.verifiedManifest.deploymentId,
    });
    const reference = await this.config.carrierVerifier.verify({
      carrier,
      expectedContext,
    });
    try {
      assertVerifiedActivePolicyReferenceV1(reference);
    } catch {
      throw new Error('verified_active_policy_reference_invalid');
    }
    const payloadBytes = encodeActivePolicyCarrierPayloadV1(carrier.payload);
    const carrierDigest = digestSignedActivePolicyCarrierV1(carrier);
    const generationContext = expectedContext;
    const activePolicyCarrier = mintVerifiedActivePolicyCarrierV1({
      carrier,
      payloadBytes,
      carrierDigest,
      carrierSignerIdentity: reference.carrierSignerIdentity,
      signerKeyId: carrier.signerKeyId,
      signerPurpose: carrier.signerPurpose,
      generationContext,
    });
    return mintVerifiedBootPolicyStateV1({
      activePolicyCarrier,
      policy: carrier.payload.activePolicy,
      authorizationEnvelope: carrier.payload.authorizationEnvelope,
      payloadBytes,
      carrierDigest,
      carrierSignerIdentity: reference.carrierSignerIdentity,
      signerKeyId: carrier.signerKeyId,
      signerPurpose: carrier.signerPurpose,
      generationContext,
    });
  }

  private carrierFromVerifiedManifest(): NonNullable<BootManifest['activePolicyCarrier']> {
    const carrier = this.config.verifiedManifest.activePolicyCarrier;
    if (!carrier) {
      throw new Error('boot_manifest_active_policy_carrier_unavailable');
    }
    return carrier;
  }
}
