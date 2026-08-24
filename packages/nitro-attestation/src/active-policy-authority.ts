import { createHash } from 'node:crypto';
import type { ActivePolicyAuthorizationEnvelopeV1 } from '@folklore/contracts';
import { encodeActivePolicyAuthorizationEnvelopeV1 } from './canonical-cbor.js';

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

function domainSeparatedDigest(domain: string, bytes: Uint8Array): Uint8Array {
  const domainBytes = Buffer.from(domain, 'utf8');
  const digest = createHash('sha256').update(bytes).digest();
  const input = new Uint8Array(domainBytes.byteLength + 1 + digest.byteLength);
  input.set(domainBytes, 0);
  input[domainBytes.byteLength] = 0;
  input.set(digest, domainBytes.byteLength + 1);
  return input;
}
