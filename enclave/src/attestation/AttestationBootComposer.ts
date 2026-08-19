import type { BootManifestRuntimeIdentity, VerifiedBootManifest } from './BootManifestVerifier.js';
import type {
  AttestationBootReadinessSnapshot,
  AttestationBootState,
} from './AttestationBootState.js';
import { RuntimeAttestationServer } from './RuntimeAttestationServer.js';
import type {
  RuntimeAttestationEvidenceCollector,
  RuntimeAttestationListener,
  RuntimeAttestationServerOptions,
} from './RuntimeAttestationServer.js';

export const attestationBootComposerErrors = {
  prepareFailed: 'attestation_boot_prepare_failed',
  statusFailed: 'attestation_boot_status_failed',
  notReady: 'runtime_attestation_not_ready',
} as const;

export type AttestationBootComposerStatus = Readonly<{
  bootManifestVerified: boolean;
  kmsUnsealed: boolean;
  hasInProcessSecrets: boolean;
  runtimeAttestationReady: boolean;
}>;

export class AttestationBootComposer {
  private readonly server: RuntimeAttestationServer;
  private enabledGeneration: number | undefined;

  constructor(
    private readonly bootState: AttestationBootState,
    private readonly collector: RuntimeAttestationEvidenceCollector,
    serverOptions: RuntimeAttestationServerOptions = {},
  ) {
    this.server = new RuntimeAttestationServer(
      { collect: (nonce) => this.collectIfReady(this.collector, nonce) },
      serverOptions,
    );
  }

  async prepare(
    signedInput: unknown,
    runtimeIdentity: BootManifestRuntimeIdentity,
  ): Promise<VerifiedBootManifest> {
    this.enabledGeneration = undefined;
    try {
      return (await this.bootState.prepareManifest(signedInput, runtimeIdentity)).manifest;
    } catch {
      throw new Error(attestationBootComposerErrors.prepareFailed);
    }
  }

  async enableRuntimeAttestation(): Promise<void> {
    const readiness = await this.readBootReadiness();
    if (!readiness.bootManifestVerified || !readiness.hasInProcessSecrets) {
      throw new Error(attestationBootComposerErrors.notReady);
    }
    this.enabledGeneration = readiness.inProcessGeneration;
  }

  async getStatus(): Promise<AttestationBootComposerStatus> {
    const readiness = await this.readBootReadiness();
    return Object.freeze({
      bootManifestVerified: readiness.bootManifestVerified,
      kmsUnsealed: readiness.kmsUnsealed,
      hasInProcessSecrets: readiness.hasInProcessSecrets,
      runtimeAttestationReady:
        readiness.bootManifestVerified &&
        readiness.hasInProcessSecrets &&
        this.enabledGeneration === readiness.inProcessGeneration,
    });
  }

  async start(listener: RuntimeAttestationListener): Promise<void> {
    await this.server.start(listener);
  }

  sign(payload: Uint8Array): { publicKey: Uint8Array; signature: Uint8Array } {
    if (this.enabledGeneration === undefined || this.collector.sign === undefined) {
      throw new Error(attestationBootComposerErrors.notReady);
    }
    return this.collector.sign(payload);
  }

  sessionPublicKey(): Uint8Array {
    if (this.enabledGeneration === undefined || this.collector.sessionPublicKey === undefined) {
      throw new Error(attestationBootComposerErrors.notReady);
    }
    return this.collector.sessionPublicKey();
  }

  handleRequest(request: Request): Promise<Response> {
    return this.server.handleRequest(request);
  }

  private async collectIfReady(
    collector: RuntimeAttestationEvidenceCollector,
    nonce: Uint8Array,
  ): ReturnType<RuntimeAttestationEvidenceCollector['collect']> {
    const status = await this.getStatus();
    if (!status.runtimeAttestationReady) {
      throw new Error(attestationBootComposerErrors.notReady);
    }
    return collector.collect(nonce);
  }

  private async readBootReadiness(): Promise<AttestationBootReadinessSnapshot> {
    try {
      return await this.bootState.getReadiness();
    } catch {
      throw new Error(attestationBootComposerErrors.statusFailed);
    }
  }
}
