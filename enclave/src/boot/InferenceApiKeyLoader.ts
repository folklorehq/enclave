import type { SsmParameterValuePort } from '../attestation/BootManifestSecretLoader.js';
import { readFailureCode } from '../attestation/read-failure-code.js';

export const inferenceApiKeyLoadErrors = {
  read: 'inference_api_key_read_failed',
  accessDenied: 'inference_api_key_access_denied',
  missing: 'inference_api_key_missing',
} as const;

/** The inference provider's API key; a failed read stops the boot by a guard slug. */
export class InferenceApiKeyLoader {
  constructor(private readonly ssm: SsmParameterValuePort) {}

  async load(path: string): Promise<string> {
    const value = await this.read(path);
    if (!value) throw new Error(inferenceApiKeyLoadErrors.missing);
    return value;
  }

  private async read(path: string): Promise<string | undefined> {
    try {
      return (await this.ssm.getParameter({ name: path, withDecryption: true })).value;
    } catch (error) {
      throw new Error(
        readFailureCode(
          error,
          inferenceApiKeyLoadErrors.read,
          inferenceApiKeyLoadErrors.accessDenied,
        ),
      );
    }
  }
}
