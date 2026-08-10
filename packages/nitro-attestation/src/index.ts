export {
  deriveAttestationUserData,
  encodeAttestationUserData,
  encodeBootManifest,
  encodeRuntimeHealthSignaturePayload,
  encodeRuntimeAttestationKeyBundle,
  hashRuntimeAttestationKeyBundle,
  hashBootManifest,
  hashNitroDocument,
  type RuntimeHealthSignaturePayload,
} from './canonical-cbor.js';
export { nitroAttestationFailureCodes, type NitroAttestationFailureCode } from './failures.js';
export {
  verifyAwsNitroAttestationDocument,
  verifyRuntimeAttestation,
  type AwsNitroAttestationDocumentResult,
  type RuntimeAttestationExpectations,
  type RuntimeAttestationResult,
  type VerifiedRuntimeIdentity,
} from './nitro-document-verifier.js';
export { derivePcr3FromRoleArn, derivePcr4FromInstanceId } from './nitro-pcr.js';
export { extractRuntimeAttestationNonce } from './runtime-attestation-nonce.js';
export {
  BootManifestKeysetError,
  encodeBootManifestKeyset,
  hashBootManifestKeyset,
  verifySignedBootManifestKeyset,
  type BootManifestKeysetVerificationFailure,
} from './boot-manifest-keyset.js';
