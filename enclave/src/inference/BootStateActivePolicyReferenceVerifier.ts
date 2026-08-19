import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import type { GenerationContextV1, SignedActivePolicyCarrierV1 } from '@folklore/contracts';
import type {
  ActivePolicyCarrierKeyVerifierPort,
  ActivePolicyCarrierVerifierPort,
  VerifiedActivePolicyReferenceV1,
} from '@folklore/inference';

// Enclave-side constructor-injected adapter over the single shared carrier verifier (plan
// Task 2). It contains no independent signature check, no local generation context, and accepts
// no caller-supplied policy, envelope, key, request, route, environment, or assignment metadata.
export class BootStateActivePolicyReferenceVerifier implements ActivePolicyCarrierVerifierPort {
  constructor(private readonly shared: ActivePolicyCarrierVerifierPort) {}

  verify(input: {
    readonly carrier: SignedActivePolicyCarrierV1;
    readonly expectedContext: GenerationContextV1;
  }): Promise<VerifiedActivePolicyReferenceV1> {
    return this.shared.verify(input);
  }
}

export interface EnclaveActivePolicyTrustedKey {
  readonly purpose: 'active-policy-carrier' | 'policy-authority';
  readonly publicKey: KeyObject;
}

// Trusted-key handoff for the enclave composition (plan Task 2). The enclave verifies only keys
// that were handed into the boot identity; until a key handoff exists the verifier rejects every
// purpose, so carrier-bearing boots fail closed instead of authorizing with an untrusted key.
export function createEnclaveActivePolicyKeyVerifier(
  trusted: ReadonlyMap<string, EnclaveActivePolicyTrustedKey> = new Map(),
): ActivePolicyCarrierKeyVerifierPort {
  return {
    async assertSignaturePurpose(input) {
      const key = trusted.get(`${input.purpose}\u0000${input.keyId}`);
      if (!key) throw new Error('enclave_active_policy_key_unavailable');
      const valid = verify(
        null,
        input.canonicalBytes,
        key.publicKey,
        Buffer.from(input.signature, 'base64'),
      );
      if (!valid) throw new Error('enclave_active_policy_signature_invalid');
    },
  };
}

export function enclaveTrustedPublicKey(rawPublicKey: Uint8Array): KeyObject {
  return createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(rawPublicKey)]),
    format: 'der',
    type: 'spki',
  });
}
