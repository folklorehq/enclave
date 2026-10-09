export const CREDENTIALS_UNAVAILABLE = 'boot_manifest_credentials_unavailable';
// The SDK's default chain throws this class when IMDS (relayed on vsock 8003) gives it nothing.
const CREDENTIALS_PROVIDER_ERROR = 'CredentialsProviderError';

/** The code for a failed AWS read: a credential failure is named apart from the read it stopped. */
export function readFailureCode(error: unknown, fallback: string): string {
  return error instanceof Error && error.name === CREDENTIALS_PROVIDER_ERROR
    ? CREDENTIALS_UNAVAILABLE
    : fallback;
}
