import type { ActivePolicyAuthorizationEnvelopeV1 } from '@folklore/contracts';
import { encodeActivePolicyAuthorizationEnvelopeV1 } from './canonical-cbor.js';
import { domainSeparatedDigest } from './model-provenance-canonical.js';

export const ACTIVE_POLICY_AUTHORITY_SIGNATURE_DOMAIN =
  'folklore.inference-trust-policy-v2-authority-signature.v1';
export const ACTIVE_POLICY_AUTHORIZATION_ENVELOPE_SIGNATURE_DOMAIN =
  'folklore.active-policy-authorization-envelope.v1';

export function activePolicyAuthoritySignatureInputV1(
  policyAuthorizationBytes: Uint8Array,
): Uint8Array {
  return domainSeparatedDigest(ACTIVE_POLICY_AUTHORITY_SIGNATURE_DOMAIN, policyAuthorizationBytes);
}

export function activePolicyAuthorizationEnvelopeSignatureInputV1(
  unsignedEnvelope: Omit<ActivePolicyAuthorizationEnvelopeV1, 'signature'>,
): Uint8Array {
  return domainSeparatedDigest(
    ACTIVE_POLICY_AUTHORIZATION_ENVELOPE_SIGNATURE_DOMAIN,
    encodeActivePolicyAuthorizationEnvelopeV1(unsignedEnvelope),
  );
}
