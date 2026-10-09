import { attestationBootStateErrors } from './AttestationBootState.js';
import { bootManifestSecretLoadErrors } from './BootManifestSecretLoader.js';
import { bootManifestVerificationErrors } from './BootManifestVerifier.js';
import { ATTESTATION_BOOT_CHECKPOINT_STORE_CODES } from './checkpoint-store-codes.js';
import { CREDENTIALS_UNAVAILABLE } from './read-failure-code.js';

export const BOOT_PREPARE_STEP_CODES: readonly string[] = Object.freeze([
  ...Object.values(bootManifestVerificationErrors),
  ...Object.values(bootManifestSecretLoadErrors),
  ...Object.values(attestationBootStateErrors),
  ...ATTESTATION_BOOT_CHECKPOINT_STORE_CODES,
  CREDENTIALS_UNAVAILABLE,
]);

const stepCodes = new Set(BOOT_PREPARE_STEP_CODES);

/** The step that stopped boot preparation, from a closed set; anything else becomes `fallback`. */
export function bootPrepareStepCode(error: unknown, fallback: string): string {
  return error instanceof Error && stepCodes.has(error.message) ? error.message : fallback;
}
