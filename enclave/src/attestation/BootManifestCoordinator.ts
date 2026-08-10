import {
  type LoadedBootManifestSecret,
  type BootManifestSecretLoader,
} from './BootManifestSecretLoader.js';
import {
  type BootManifestRuntimeIdentity,
  type BootManifestVerifier,
  type VerifiedBootManifest,
} from './BootManifestVerifier.js';

export interface BootManifestVerifierPort {
  verify(input: unknown, runtimeIdentity: BootManifestRuntimeIdentity): VerifiedBootManifest;
}

export interface BootManifestSecretLoaderPort {
  load(
    manifest: Pick<VerifiedBootManifest, 'secretReferences'>,
  ): Promise<readonly LoadedBootManifestSecret[]>;
}

export type BootManifestCoordinatorResult = Readonly<{
  manifest: VerifiedBootManifest;
  secrets: readonly LoadedBootManifestSecret[];
}>;

export class BootManifestCoordinator {
  constructor(
    private readonly verifier: BootManifestVerifier | BootManifestVerifierPort,
    private readonly secretLoader: BootManifestSecretLoader | BootManifestSecretLoaderPort,
  ) {}

  async verifyAndLoad(
    input: unknown,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): Promise<BootManifestCoordinatorResult> {
    const manifest = this.verifier.verify(input, runtimeIdentity);
    const secrets = await this.secretLoader.load({ secretReferences: manifest.secretReferences });
    return Object.freeze({ manifest, secrets: this.ownedSecrets(secrets) });
  }

  private ownedSecrets(
    secrets: readonly LoadedBootManifestSecret[],
  ): readonly LoadedBootManifestSecret[] {
    return Object.freeze(secrets.map((secret) => Object.freeze({ ...secret })));
  }
}
