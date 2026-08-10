import {
  bootManifestSecretReferenceSchema,
  type BootManifestSecretReference,
} from '@folklore/contracts/enclave-attestation';
import type { VerifiedBootManifest } from './BootManifestVerifier.js';

const DEFAULT_MAX_SECRET_VALUE_BYTES = 64 * 1024;

export const bootManifestSecretLoadErrors = {
  reference: 'boot_manifest_secret_reference_invalid',
  missing: 'boot_manifest_secret_missing',
  identity: 'boot_manifest_secret_identity_invalid',
  version: 'boot_manifest_secret_version_invalid',
  value: 'boot_manifest_secret_value_invalid',
  bound: 'boot_manifest_secret_value_too_large',
} as const;

export interface SecretsManagerSecretValuePort {
  getSecretValue(input: { secretId: string; versionId: string }): Promise<{
    arn?: string;
    versionId?: string;
    secretString?: string;
    secretBinary?: Uint8Array;
  }>;
}

export interface SsmParameterValuePort {
  getParameter(input: { name: string; version: number }): Promise<{
    name?: string;
    version?: number;
    value?: string;
  }>;
}

export type LoadedBootManifestSecret = Readonly<{
  id: string;
  store: 'secrets-manager' | 'ssm';
  value: string;
}>;

export class BootManifestSecretLoader {
  readonly #maxValueBytes: number;

  constructor(
    private readonly secretsManager: SecretsManagerSecretValuePort,
    private readonly ssm: SsmParameterValuePort,
    options: { maxValueBytes?: number } = {},
  ) {
    this.#maxValueBytes = this.maxValueBytes(options.maxValueBytes);
  }

  async load(
    manifest: Pick<VerifiedBootManifest, 'secretReferences'>,
  ): Promise<readonly LoadedBootManifestSecret[]> {
    const references = this.validReferences(manifest);
    const loaded: LoadedBootManifestSecret[] = [];
    for (const reference of references) {
      loaded.push(await this.loadReference(reference));
    }
    return Object.freeze(loaded);
  }

  private validReferences(
    manifest: Pick<VerifiedBootManifest, 'secretReferences'>,
  ): readonly BootManifestSecretReference[] {
    if (
      !manifest ||
      !Array.isArray(manifest.secretReferences) ||
      manifest.secretReferences.length === 0
    ) {
      throw new Error(bootManifestSecretLoadErrors.reference);
    }
    return manifest.secretReferences.map((reference) => {
      const parsed = bootManifestSecretReferenceSchema.safeParse(reference);
      if (!parsed.success) throw new Error(bootManifestSecretLoadErrors.reference);
      return parsed.data;
    });
  }

  private async loadReference(
    reference: BootManifestSecretReference,
  ): Promise<LoadedBootManifestSecret> {
    if (reference.store === 'secrets-manager') return this.loadSecretsManager(reference);
    return this.loadSsm(reference);
  }

  private async loadSecretsManager(
    reference: Extract<BootManifestSecretReference, { store: 'secrets-manager' }>,
  ): Promise<LoadedBootManifestSecret> {
    const response = await this.readSecretsManager(reference);
    if (response.arn !== reference.arn) throw new Error(bootManifestSecretLoadErrors.identity);
    if (response.versionId !== reference.versionId)
      throw new Error(bootManifestSecretLoadErrors.version);
    const value = this.validValue(response.secretString);
    return Object.freeze({ id: reference.id, store: reference.store, value });
  }

  private async readSecretsManager(
    reference: Extract<BootManifestSecretReference, { store: 'secrets-manager' }>,
  ): ReturnType<SecretsManagerSecretValuePort['getSecretValue']> {
    try {
      return await this.secretsManager.getSecretValue({
        secretId: reference.arn,
        versionId: reference.versionId,
      });
    } catch {
      throw new Error(bootManifestSecretLoadErrors.missing);
    }
  }

  private async loadSsm(
    reference: Extract<BootManifestSecretReference, { store: 'ssm' }>,
  ): Promise<LoadedBootManifestSecret> {
    const response = await this.readSsm(reference);
    if (response.name !== reference.path) throw new Error(bootManifestSecretLoadErrors.identity);
    if (response.version !== reference.version)
      throw new Error(bootManifestSecretLoadErrors.version);
    const value = this.validValue(response.value);
    return Object.freeze({ id: reference.id, store: reference.store, value });
  }

  private async readSsm(
    reference: Extract<BootManifestSecretReference, { store: 'ssm' }>,
  ): ReturnType<SsmParameterValuePort['getParameter']> {
    try {
      return await this.ssm.getParameter({ name: reference.path, version: reference.version });
    } catch {
      throw new Error(bootManifestSecretLoadErrors.missing);
    }
  }

  private validValue(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(bootManifestSecretLoadErrors.value);
    }
    if (Buffer.byteLength(value, 'utf8') > this.#maxValueBytes) {
      throw new Error(bootManifestSecretLoadErrors.bound);
    }
    return value.slice(0);
  }

  private maxValueBytes(value: number | undefined): number {
    if (value === undefined) return DEFAULT_MAX_SECRET_VALUE_BYTES;
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new Error(bootManifestSecretLoadErrors.bound);
    return value;
  }
}
