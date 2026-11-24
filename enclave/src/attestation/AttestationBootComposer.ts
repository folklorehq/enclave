import type { BootManifestRuntimeIdentity, VerifiedBootManifest } from './BootManifestVerifier.js';
import type { AttestationBootState } from './AttestationBootState.js';
import { bootPrepareStepCode } from './boot-prepare-failure.js';

export const attestationBootComposerErrors = {
  prepareFailed: 'attestation_boot_prepare_failed',
} as const;

export class AttestationBootComposer {
  constructor(private readonly bootState: AttestationBootState) {}

  async prepare(
    signedInput: unknown,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): Promise<VerifiedBootManifest> {
    try {
      return (await this.bootState.prepareManifest(signedInput, runtimeIdentity)).manifest;
    } catch (error) {
      throw new Error(bootPrepareStepCode(error, attestationBootComposerErrors.prepareFailed));
    }
  }
}
