import { decode } from 'cborg';
import {
  activePolicyCarrierPayloadV1Schema,
  signedActivePolicyCarrierV1Schema,
  type ActivePolicyCarrierPayloadV1,
  type ActivePolicyCarrierProtectedPolicyReferenceV1,
  type GenerationContextV1,
  type SignedActivePolicyCarrierV1,
} from '@folklore/contracts';
import {
  encodeActiveInferenceTrustPolicyV2,
  encodeActivePolicyAuthorizationEnvelopeV1,
} from './canonical-cbor.js';
import { domainSeparatedBytes, sha256Hex } from './model-provenance-canonical.js';
import { canonicalCbor } from './canonical-cbor.js';

export const ACTIVE_POLICY_CARRIER_PAYLOAD_V1_DOMAIN = 'folklore.active-policy-carrier-payload.v1';
export const SIGNED_ACTIVE_POLICY_CARRIER_V1_DOMAIN = 'folklore.signed-active-policy-carrier.v1';

// The payload embeds the active policy and its authorization envelope in canonical array form
// (produced by the existing canonical encoders and decoded once), plus the exact ordered
// GenerationContextV1 and protected policy reference. One canonical CBOR encode per value; never
// JSON stringification and never re-encoding already-canonical bytes.

export function activePolicyCarrierGenerationContextArrayV1(
  context: GenerationContextV1,
): unknown[] {
  return [
    context.orgId,
    context.deploymentId,
    context.policyDigest,
    context.policyGeneration,
    context.activationGeneration,
    context.configurationGeneration,
    context.keysetEpoch,
    context.keysetDigest,
    context.releaseId,
    context.protectedSourceCommit,
    context.eifDigest,
    context.pcr0,
    context.bootRootDigest,
  ];
}

export function activePolicyCarrierProtectedPolicyReferenceArrayV1(
  reference: ActivePolicyCarrierProtectedPolicyReferenceV1,
): unknown[] {
  return [
    reference.orgId,
    reference.deploymentId,
    reference.policyDigest,
    reference.policyGeneration,
    reference.activationGeneration,
    reference.configurationGeneration,
    reference.keysetEpoch,
    reference.keysetDigest,
  ];
}

function activePolicyArray(policy: ActivePolicyCarrierPayloadV1['activePolicy']): unknown[] {
  return decode(encodeActiveInferenceTrustPolicyV2(policy));
}

function authorizationEnvelopeArray(
  envelope: ActivePolicyCarrierPayloadV1['authorizationEnvelope'],
): unknown[] {
  const { signature, ...unsignedEnvelope } = envelope;
  return [...decode(encodeActivePolicyAuthorizationEnvelopeV1(unsignedEnvelope)), signature];
}

export function activePolicyCarrierPayloadArrayV1(input: ActivePolicyCarrierPayloadV1): unknown[] {
  const payload = activePolicyCarrierPayloadV1Schema.parse(input);
  return [
    payload.schema,
    payload.orgId,
    payload.deploymentId,
    activePolicyArray(payload.activePolicy),
    authorizationEnvelopeArray(payload.authorizationEnvelope),
    activePolicyCarrierGenerationContextArrayV1(payload.generationContext),
    activePolicyCarrierProtectedPolicyReferenceArrayV1(payload.protectedPolicyReference),
  ];
}

export function encodeActivePolicyCarrierPayloadV1(
  input: ActivePolicyCarrierPayloadV1,
): Uint8Array {
  return canonicalCbor(activePolicyCarrierPayloadArrayV1(input));
}

// The exact bytes the carrier signer signs and the shared verifier checks: UTF8(domain) || 0x00 ||
// canonicalCBOR(payloadArray).
export function activePolicyCarrierPayloadSignatureInputV1(
  input: ActivePolicyCarrierPayloadV1,
): Uint8Array {
  return domainSeparatedBytes(
    ACTIVE_POLICY_CARRIER_PAYLOAD_V1_DOMAIN,
    activePolicyCarrierPayloadArrayV1(input),
  );
}

export function digestActivePolicyCarrierPayloadV1(input: ActivePolicyCarrierPayloadV1): string {
  return sha256Hex(encodeActivePolicyCarrierPayloadV1(input));
}

export function signedActivePolicyCarrierArrayV1(input: SignedActivePolicyCarrierV1): unknown[] {
  const carrier = signedActivePolicyCarrierV1Schema.parse(input);
  return [
    carrier.schema,
    digestActivePolicyCarrierPayloadV1(carrier.payload),
    carrier.algorithm,
    carrier.signerKeyId,
    carrier.signerPurpose,
    carrier.signature,
  ];
}

export function encodeSignedActivePolicyCarrierV1(input: SignedActivePolicyCarrierV1): Uint8Array {
  return canonicalCbor(signedActivePolicyCarrierArrayV1(input));
}

export function digestSignedActivePolicyCarrierV1(input: SignedActivePolicyCarrierV1): string {
  return sha256Hex(
    domainSeparatedBytes(
      SIGNED_ACTIVE_POLICY_CARRIER_V1_DOMAIN,
      signedActivePolicyCarrierArrayV1(input),
    ),
  );
}
