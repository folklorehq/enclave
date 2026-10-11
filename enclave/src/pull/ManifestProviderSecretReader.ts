import type { BootManifestSecretReference } from '@folklore/contracts/enclave-attestation';
import type { SecretsManagerSecretValuePort } from '../attestation/BootManifestSecretLoader.js';

export const manifestProviderSecretErrors = {
  reference: 'oauth_provider_secret_reference_invalid',
  version: 'oauth_provider_secret_version_mismatch',
  value: 'oauth_provider_secret_value_invalid',
  encoding: 'oauth_provider_secret_encoding_invalid',
} as const;

type SecretsManagerReference = Extract<BootManifestSecretReference, { store: 'secrets-manager' }>;

// Envelopes are base64 SecretStrings because the boot loader refuses a manifest secret without one.
export class ManifestProviderSecretReader {
  constructor(
    private readonly secrets: SecretsManagerSecretValuePort,
    private readonly references: ReadonlyMap<string, BootManifestSecretReference>,
  ) {}

  async read(input: { secretId: string }): Promise<Uint8Array> {
    const reference = this.secretsManagerReference(input.secretId);
    const response = await this.secrets.getSecretValue({
      secretId: reference.arn,
      versionId: reference.versionId,
    });
    if (response.arn !== reference.arn || response.versionId !== reference.versionId) {
      throw new Error(manifestProviderSecretErrors.version);
    }
    return this.decodeBase64(response.secretString);
  }

  assertReference(secretId: string): void {
    this.secretsManagerReference(secretId);
  }

  private secretsManagerReference(secretId: string): SecretsManagerReference {
    const reference = this.references.get(secretId);
    if (!reference || reference.store !== 'secrets-manager') {
      throw new Error(manifestProviderSecretErrors.reference);
    }
    return reference;
  }

  private decodeBase64(value: string | undefined): Uint8Array {
    if (!value) throw new Error(manifestProviderSecretErrors.value);
    const decoded = Buffer.from(value, 'base64');
    if (decoded.toString('base64') !== value) {
      decoded.fill(0);
      throw new Error(manifestProviderSecretErrors.encoding);
    }
    return decoded;
  }
}
