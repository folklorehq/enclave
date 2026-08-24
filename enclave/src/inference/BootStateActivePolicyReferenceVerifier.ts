import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { DescribeKeyCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import type {
  ActivePolicyAuthorityIdentityV1,
  ActivePolicyCarrierSignerIdentityV1,
  GenerationContextV1,
  SignedActivePolicyCarrierV1,
} from '@folklore/contracts';
import type { ActivePolicyBootTrust } from '@folklore/contracts/enclave-attestation';
import type {
  ActivePolicyCarrierKeyVerifierPort,
  ActivePolicyCarrierVerifierPort,
  VerifiedActivePolicyReferenceV1,
} from '@folklore/inference';

// Enclave-side constructor-injected adapter over the single shared carrier verifier. It contains no independent signature check, no local generation context, and accepts
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

const BOOT_BOUND_GENERATION_FIELDS = [
  'configurationGeneration',
  'releaseId',
  'protectedSourceCommit',
  'eifDigest',
  'pcr0',
  'bootRootDigest',
] as const;

export type BootBoundGenerationContext = Pick<
  GenerationContextV1,
  | 'configurationGeneration'
  | 'releaseId'
  | 'protectedSourceCommit'
  | 'eifDigest'
  | 'pcr0'
  | 'bootRootDigest'
>;

export function buildV4ExpectedGenerationContext(input: {
  readonly bootContext: BootBoundGenerationContext;
  readonly carrierContext: GenerationContextV1;
  readonly tenantId: string;
  readonly deploymentId: string;
}): GenerationContextV1 {
  for (const field of BOOT_BOUND_GENERATION_FIELDS) {
    if (input.carrierContext[field] !== input.bootContext[field]) {
      throw new Error('active_policy_boot_context_mismatch');
    }
  }
  if (
    input.carrierContext.orgId !== input.tenantId ||
    input.carrierContext.deploymentId !== input.deploymentId
  ) {
    throw new Error('active_policy_assignment_context_mismatch');
  }
  return {
    ...input.bootContext,
    orgId: input.tenantId,
    deploymentId: input.deploymentId,
    policyDigest: input.carrierContext.policyDigest,
    policyGeneration: input.carrierContext.policyGeneration,
    activationGeneration: input.carrierContext.activationGeneration,
    keysetEpoch: input.carrierContext.keysetEpoch,
    keysetDigest: input.carrierContext.keysetDigest,
  };
}

export interface EnclaveActivePolicyTrustedKey {
  readonly purpose: 'active-policy-carrier' | 'policy-authority';
  readonly publicKey: KeyObject;
}

export interface EnclaveActivePolicyKmsClient {
  send(command: DescribeKeyCommand | GetPublicKeyCommand): Promise<{
    readonly KeyMetadata?: {
      readonly Arn?: string;
      readonly KeyId?: string;
      readonly Enabled?: boolean;
      readonly KeySpec?: string;
      readonly KeyUsage?: string;
      readonly KeyManager?: string;
      readonly Origin?: string;
      readonly MultiRegion?: boolean;
      readonly SigningAlgorithms?: readonly string[];
    };
    readonly KeyId?: string;
    readonly PublicKey?: Uint8Array;
    readonly KeySpec?: string;
    readonly KeyUsage?: string;
    readonly SigningAlgorithms?: readonly string[];
  }>;
}

export interface EnclaveActivePolicyTrust {
  readonly authority: ActivePolicyAuthorityIdentityV1;
  readonly carrierSigner: ActivePolicyCarrierSignerIdentityV1;
  readonly keyVerifier: ActivePolicyCarrierKeyVerifierPort;
}

// Trusted-key handoff for the enclave composition. The enclave verifies only keys
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

export async function loadEnclaveActivePolicyTrust(input: {
  readonly bootTrust: ActivePolicyBootTrust;
  readonly kms: EnclaveActivePolicyKmsClient;
}): Promise<EnclaveActivePolicyTrust> {
  if (
    input.bootTrust.schema !== 'folklore.active-policy-boot-trust.v2' ||
    !input.bootTrust.carrierSigner
  ) {
    throw new Error('enclave_active_policy_boot_trust_invalid');
  }
  const authority = Object.freeze({ ...input.bootTrust.authority });
  const carrierSigner = Object.freeze({ ...input.bootTrust.carrierSigner });
  if (
    authority.keyArn === carrierSigner.keyArn ||
    authority.keyId === carrierSigner.keyId ||
    authority.publicKeySpkiSha256 === carrierSigner.publicKeySpkiSha256
  ) {
    throw new Error('enclave_active_policy_signer_identity_collision');
  }
  const authorityPublicKey = await loadEnclaveActivePolicyPublicKey({
    identity: authority,
    kms: input.kms,
    invalidIdentityError: 'enclave_active_policy_authority_invalid',
  });
  const carrierPublicKey = await loadEnclaveActivePolicyPublicKey({
    identity: carrierSigner,
    kms: input.kms,
    invalidIdentityError: 'enclave_active_policy_carrier_signer_invalid',
  });
  const trusted = new Map<string, EnclaveActivePolicyTrustedKey>([
    [
      `active-policy-carrier\u0000${carrierSigner.keyId}`,
      { purpose: 'active-policy-carrier', publicKey: carrierPublicKey },
    ],
    [
      `policy-authority\u0000${authority.keyId}`,
      { purpose: 'policy-authority', publicKey: authorityPublicKey },
    ],
  ]);
  return {
    authority,
    carrierSigner,
    keyVerifier: createEnclaveActivePolicyKeyVerifier(trusted),
  };
}

async function loadEnclaveActivePolicyPublicKey(input: {
  readonly identity: ActivePolicyAuthorityIdentityV1 | ActivePolicyCarrierSignerIdentityV1;
  readonly kms: EnclaveActivePolicyKmsClient;
  readonly invalidIdentityError: string;
}): Promise<KeyObject> {
  const identity = input.identity;
  if (
    !identity.keyArn ||
    !identity.keyId ||
    !identity.publicKeySpkiSha256 ||
    !Number.isSafeInteger(identity.epoch) ||
    identity.epoch <= 0
  ) {
    throw new Error(input.invalidIdentityError);
  }
  const description = await input.kms.send(new DescribeKeyCommand({ KeyId: identity.keyArn }));
  const metadata = description.KeyMetadata;
  if (
    metadata?.Arn !== identity.keyArn ||
    metadata.KeyId !== identity.keyId ||
    metadata.Enabled !== true ||
    metadata.KeySpec !== 'ECC_NIST_EDWARDS25519' ||
    metadata.KeyUsage !== 'SIGN_VERIFY' ||
    metadata.KeyManager !== 'CUSTOMER' ||
    metadata.Origin !== 'AWS_KMS' ||
    metadata.MultiRegion !== false ||
    metadata.SigningAlgorithms?.length !== 1 ||
    metadata.SigningAlgorithms[0] !== 'ED25519_SHA_512'
  ) {
    throw new Error('enclave_active_policy_kms_metadata_mismatch');
  }
  const response = await input.kms.send(new GetPublicKeyCommand({ KeyId: identity.keyArn }));
  if (
    response.KeyId !== identity.keyArn ||
    response.KeySpec !== 'ECC_NIST_EDWARDS25519' ||
    response.KeyUsage !== 'SIGN_VERIFY' ||
    response.SigningAlgorithms?.length !== 1 ||
    response.SigningAlgorithms[0] !== 'ED25519_SHA_512' ||
    !response.PublicKey
  ) {
    throw new Error('enclave_active_policy_kms_metadata_mismatch');
  }
  const publicKeySpkiSha256 = createHash('sha256').update(response.PublicKey).digest('hex');
  if (publicKeySpkiSha256 !== identity.publicKeySpkiSha256) {
    throw new Error('enclave_active_policy_public_key_mismatch');
  }
  return createPublicKey({
    key: Buffer.from(response.PublicKey),
    format: 'der',
    type: 'spki',
  });
}
