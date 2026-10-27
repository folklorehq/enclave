import type { SsmParameterValuePort } from '../attestation/BootManifestSecretLoader.js';
import { SsmSecretLoader } from './SsmSecretLoader.js';

export const inferenceApiKeyLoadErrors = {
  read: 'inference_api_key_read_failed',
  accessDenied: 'inference_api_key_access_denied',
  missing: 'inference_api_key_missing',
} as const;

/** The inference provider's API key; a failed read stops the boot by a guard slug. */
export class InferenceApiKeyLoader extends SsmSecretLoader {
  constructor(ssm: SsmParameterValuePort) {
    super(ssm, inferenceApiKeyLoadErrors);
  }
}
