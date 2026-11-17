import { isServiceFault } from './service-fault.js';

// The ESDK KMS keyring folds every per-key KMS error into one plain Error with no $metadata: this prefix,
// then " Error #<n> \n <stack>" for each, and each stack starts with "<AwsErrorName>: <message>".
const AGGREGATED_KMS_PREFIX = 'Unable to decrypt data key and one or more KMS CMKs had an error.';
const EMBEDDED_ERROR_NAME = /Error #\d+ \n (\w+)/g;

// Only these say the ciphertext itself is bad; any other name, known or not, is treated as an outage.
const UNDECRYPTABLE_NAMES: ReadonlySet<string> = new Set([
  'InvalidCiphertextException',
  'IncorrectKeyException',
]);
const OPERATIONAL_NAMES: ReadonlySet<string> = new Set([
  'AccessDeniedException',
  'TimeoutError',
  'NetworkingError',
]);
const OPERATIONAL_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
]);

export type EsdkFailure = 'operational' | 'undecryptable';

export function classifyEsdkFailure(error: unknown): EsdkFailure {
  if (isServiceFault(error) || hasOperationalNameOrCode(error)) return 'operational';
  if (!(error instanceof Error) || !error.message.startsWith(AGGREGATED_KMS_PREFIX)) {
    return 'undecryptable';
  }
  const names = [...error.message.matchAll(EMBEDDED_ERROR_NAME)].map((match) => match[1] ?? '');
  const allUndecryptable = names.length > 0 && names.every((name) => UNDECRYPTABLE_NAMES.has(name));
  return allUndecryptable ? 'undecryptable' : 'operational';
}

function hasOperationalNameOrCode(error: unknown): boolean {
  const { name, code } = (error ?? {}) as { name?: unknown; code?: unknown };
  return OPERATIONAL_NAMES.has(String(name)) || OPERATIONAL_CODES.has(String(code));
}
