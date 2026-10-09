import { enclaveOutputAuthenticatorErrors } from '@folklore/crypto';

const ENCLAVE_OUTPUT_SIGNER_INVALID = 'enclave_output_signer_invalid';
const NAMED_FAILURES: ReadonlySet<string> = new Set(
  Object.values(enclaveOutputAuthenticatorErrors),
);

export function enclaveOutputSignerFailureCode(error: unknown): string {
  return error instanceof Error && NAMED_FAILURES.has(error.message)
    ? error.message
    : ENCLAVE_OUTPUT_SIGNER_INVALID;
}
