import {
  digestSignedActivePolicyCarrierV1,
  encodeActivePolicyCarrierPayloadV1,
} from '@folklore/nitro-attestation';
import type { GenerationContextV1 } from '@folklore/contracts';
import {
  assertVerifiedActivePolicyReferenceV1,
  mintVerifiedActivePolicyCarrierV1,
  mintVerifiedBootPolicyStateV1,
  type ActivePolicyCarrierVerifierPort,
  type VerifiedBootPolicyStateV1,
} from '@folklore/inference';
import type { BootManifest } from '@folklore/contracts/enclave-attestation';
import type { VerifiedBootManifest } from './BootManifestVerifier.js';

// The only boot-to-enclave accessor for verified active-policy state (plan Task 2). No
// composition root may pass a policy object, reference URL, receipt metadata, environment
// variable, or assignment metadata as policy authority: the loader reads the signed carrier
// solely from the verified boot manifest, verifies it through the shared carrier verifier, and
// mints the opaque boot-state brand. A reference-only manifest or a caller-supplied policy fails
// here, before any snapshot or tuple can be produced.
export interface VerifiedBootPolicyStateLoaderConfig {
  readonly verifiedManifest: VerifiedBootManifest;
  readonly carrierVerifier: ActivePolicyCarrierVerifierPort;
}

export function buildVerifiedBootGenerationContext(
  manifest: VerifiedBootManifest,
  carrier: NonNullable<BootManifest['activePolicyCarrier']>,
): GenerationContextV1 {
  const context = carrier.payload.generationContext;
  return {
    // Manifest-signed boot identity: the carrier must match these exactly.
    orgId: manifest.orgId,
    deploymentId: manifest.deploymentId,
    configurationGeneration: manifest.configurationGeneration,
    eifDigest: manifest.eifDigest,
    protectedSourceCommit: manifest.sourceSha,
    // Carrier-signed release and policy identity: verified for self-consistency by the shared
    // carrier verifier and bound to the manifest identity above.
    releaseId: context.releaseId,
    pcr0: context.pcr0,
    bootRootDigest: context.bootRootDigest,
    policyDigest: context.policyDigest,
    policyGeneration: context.policyGeneration,
    activationGeneration: context.activationGeneration,
    keysetEpoch: context.keysetEpoch,
    keysetDigest: context.keysetDigest,
  };
}

export class VerifiedBootPolicyStateLoader {
  constructor(private readonly config: VerifiedBootPolicyStateLoaderConfig) {}

  async loadVerifiedBootPolicyState(): Promise<VerifiedBootPolicyStateV1> {
    const carrier = this.carrierFromVerifiedManifest();
    const expectedContext = buildVerifiedBootGenerationContext(
      this.config.verifiedManifest,
      carrier,
    );
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
