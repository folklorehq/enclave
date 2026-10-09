export const CREDENTIALS_UNAVAILABLE = 'boot_manifest_credentials_unavailable';
// The SDK's default chain throws this class when IMDS (relayed on vsock 8003) gives it nothing.
const CREDENTIALS_PROVIDER_ERROR = 'CredentialsProviderError';
// SSM, KMS and Secrets Manager name a refusal AccessDeniedException; S3 names it AccessDenied.
const ACCESS_DENIED_ERRORS: ReadonlySet<string> = new Set([
  'AccessDeniedException',
  'AccessDenied',
]);

/** The code for a failed AWS read: a credential failure, and a refusal when the caller names one, apart from the read. */
export function readFailureCode(error: unknown, fallback: string, accessDenied?: string): string {
  if (!(error instanceof Error)) return fallback;
  if (error.name === CREDENTIALS_PROVIDER_ERROR) return CREDENTIALS_UNAVAILABLE;
  return accessDenied !== undefined && ACCESS_DENIED_ERRORS.has(error.name)
    ? accessDenied
    : fallback;
}
