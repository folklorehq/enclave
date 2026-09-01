// Dev-only KMS-stub gate, shared by every seam that swaps attested KMS for a localstack-friendly
// path (master-key sealers and the seal.ts content/secret decrypt branch). One definition so the
// two crypto seams can never drift to different notions of "this is a dev process". The production
// EIF pins NODE_ENV=production in entrypoint.sh AND denies ENCLAVE_DEV_KMS_STUB from the parent env
// (aws-transport/egress-allowlist tests), so this gate can never pass inside the EIF.
export function assertDevKmsStubAllowed(nodeEnv: string): void {
  if (nodeEnv !== 'development' && nodeEnv !== 'test') {
    throw new Error('ENCLAVE_DEV_KMS_STUB is development-only (NODE_ENV must be development)');
  }
}
