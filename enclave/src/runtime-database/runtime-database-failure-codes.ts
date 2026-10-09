import { RUNTIME_DATABASE_READINESS_FAILURE_CODES } from '@folklore/contracts/enclave-attestation';

export const RUNTIME_DATABASE_CREDENTIAL_ERROR_CODES = [
  'runtime_database_config_invalid',
  'runtime_database_parameter_unavailable',
  'runtime_database_envelope_invalid',
  'runtime_database_kms_response_invalid',
  'runtime_database_credential_invalid',
  'runtime_database_readiness_failed',
  ...RUNTIME_DATABASE_READINESS_FAILURE_CODES,
] as const;
export type RuntimeDatabaseCredentialErrorCode =
  (typeof RUNTIME_DATABASE_CREDENTIAL_ERROR_CODES)[number];

export const RUNTIME_DATABASE_SIGNED_CONFIG_UNAVAILABLE =
  'runtime_database_signed_config_unavailable';
export const RUNTIME_DATABASE_API_UNAVAILABLE = 'runtime_database_api_unavailable';

const activationFailureCodes: ReadonlySet<unknown> = new Set([
  ...RUNTIME_DATABASE_CREDENTIAL_ERROR_CODES,
  RUNTIME_DATABASE_SIGNED_CONFIG_UNAVAILABLE,
  RUNTIME_DATABASE_API_UNAVAILABLE,
]);

/** True only for a fixed code a runtime database activation can fail with. */
export function isRuntimeDatabaseActivationFailureCode(value: unknown): value is string {
  return activationFailureCodes.has(value);
}

const RUNTIME_DATABASE_CODE_PREFIX = 'runtime_database_';

/** True for a slug in the runtime database namespace that is not one of its fixed codes. */
export function isUnlistedRuntimeDatabaseCode(value: string): boolean {
  return (
    value.startsWith(RUNTIME_DATABASE_CODE_PREFIX) && !isRuntimeDatabaseActivationFailureCode(value)
  );
}
