import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
  enclaveRuntimeEvidenceSchema,
  poolRuntimeAttestationUserDataSchema,
  type EnclaveRuntimeEvidence,
  type PoolRuntimeAttestationUserData,
  type RuntimeDatabaseCredentialReceipt,
} from '@folklore/contracts/enclave-attestation';
import {
  encodePoolRuntimeAttestationUserData,
  encodePoolRuntimeHealthSignaturePayload,
  hashNitroDocument,
} from '@folklore/nitro-attestation';
import type { NsmAttestationPort } from '../../sealing/nsm.js';

const NONCE_BYTES = 32;
const MAX_NITRO_DOCUMENT_BYTES = 16_384;
const NONCE_WINDOW = 8;

export interface PoolRuntimeReadiness {
  poolDeploymentId: string;
  assignmentGeneration: number;
  assignmentDigest: string;
  assignmentManifestVerified: boolean;
  tenantAssigned: boolean;
  tenantApiReady: boolean;
  runtimeDatabase?: RuntimeDatabaseCredentialReceipt;
}

export class PoolRuntimeAttestationService {
  readonly #usedNonces = new Set<string>();
  readonly #nonceOrder: string[] = [];
  #session: { privateKey: KeyObject; publicKey: Uint8Array } | undefined;
  #attestedBinding: string | undefined;
  #collecting = false;

  constructor(
    private readonly readiness: () => PoolRuntimeReadiness | Promise<PoolRuntimeReadiness>,
    private readonly nsm: NsmAttestationPort,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async collect(nonce: Uint8Array): Promise<EnclaveRuntimeEvidence> {
    this.claimNonce(nonce);
    try {
      const ready = await this.ready();
      const session = this.session();
      const userData = this.userData(ready, session.publicKey);
      const document = await this.nsm.attest({
        publicKey: session.publicKey,
        nonce: Uint8Array.from(nonce),
        userData: encodePoolRuntimeAttestationUserData(userData),
      });
      if (
        !(document instanceof Uint8Array) ||
        document.byteLength === 0 ||
        document.byteLength > MAX_NITRO_DOCUMENT_BYTES
      ) {
        throw new Error('runtime_attestation_failed');
      }
      const observedAt = this.now();
      if (!Number.isFinite(observedAt.getTime())) throw new Error('runtime_attestation_failed');
      const record = {
        version: 1 as const,
        observedAt: observedAt.toISOString(),
        status: 'healthy' as const,
        tenantAssigned: true,
        bootManifestVerified: false,
        runtimeTrust: 'pool-assignment' as const,
        assignmentManifestVerified: ready.assignmentManifestVerified as true,
        kmsUnsealed: true,
        tenantApiReady: true,
        runtimeDatabase: ready.runtimeDatabase,
      };
      const signature = sign(
        null,
        encodePoolRuntimeHealthSignaturePayload({
          nonce,
          documentHash: hashNitroDocument(document),
          userData,
          record,
        }),
        session.privateKey,
      );
      this.#attestedBinding = this.bindingKey(ready);
      return enclaveRuntimeEvidenceSchema.parse({
        version: 1,
        nitroDocument: Buffer.from(document).toString('base64'),
        sessionPublicKey: Buffer.from(session.publicKey).toString('base64'),
        signedHealth: { version: 1, record, signature: signature.toString('base64') },
      });
    } finally {
      this.#collecting = false;
    }
  }

  async signCurrent(
    payload: Uint8Array,
  ): Promise<{ publicKey: Uint8Array; signature: Uint8Array }> {
    const ready = await this.ready();
    const session = this.#session;
    if (!session || this.#attestedBinding !== this.bindingKey(ready) || payload.byteLength === 0) {
      throw new Error('runtime_attestation_not_ready');
    }
    return {
      publicKey: Uint8Array.from(session.publicKey),
      signature: Uint8Array.from(sign(null, payload, session.privateKey)),
    };
  }

  async currentSessionPublicKey(): Promise<Uint8Array> {
    const ready = await this.ready();
    const session = this.#session;
    if (!session || this.#attestedBinding !== this.bindingKey(ready)) {
      throw new Error('runtime_attestation_not_ready');
    }
    return Uint8Array.from(session.publicKey);
  }

  private async ready(): Promise<
    PoolRuntimeReadiness & { runtimeDatabase: RuntimeDatabaseCredentialReceipt }
  > {
    const ready = await this.readiness();
    if (
      !ready.assignmentManifestVerified ||
      !ready.tenantAssigned ||
      !ready.tenantApiReady ||
      !ready.runtimeDatabase
    ) {
      throw new Error('runtime_attestation_not_ready');
    }
    poolRuntimeAttestationUserDataSchema.parse(
      this.userData(
        ready as PoolRuntimeReadiness & { runtimeDatabase: RuntimeDatabaseCredentialReceipt },
        new Uint8Array(32),
      ),
    );
    return ready as PoolRuntimeReadiness & { runtimeDatabase: RuntimeDatabaseCredentialReceipt };
  }

  private userData(
    ready: PoolRuntimeReadiness & { runtimeDatabase: RuntimeDatabaseCredentialReceipt },
    sessionPublicKey: Uint8Array,
  ): PoolRuntimeAttestationUserData {
    return {
      version: 1,
      poolDeploymentId: ready.poolDeploymentId,
      assignmentGeneration: ready.assignmentGeneration,
      assignmentDigest: ready.assignmentDigest,
      runtimeDatabase: ready.runtimeDatabase,
      sessionPublicKeySha256: createHash('sha256').update(sessionPublicKey).digest('hex'),
    };
  }

  private session(): { privateKey: KeyObject; publicKey: Uint8Array } {
    if (this.#session) return this.#session;
    const pair = generateKeyPairSync('ed25519');
    const der = pair.publicKey.export({ type: 'spki', format: 'der' });
    this.#session = {
      privateKey: pair.privateKey,
      publicKey: Uint8Array.from(Buffer.from(der).subarray(-32)),
    };
    return this.#session;
  }

  private bindingKey(ready: PoolRuntimeReadiness): string {
    return JSON.stringify([
      ready.poolDeploymentId,
      ready.assignmentGeneration,
      ready.assignmentDigest,
      ready.runtimeDatabase,
    ]);
  }

  private claimNonce(nonce: Uint8Array): string {
    if (!(nonce instanceof Uint8Array) || nonce.byteLength !== NONCE_BYTES) {
      throw new Error('runtime_attestation_invalid_nonce');
    }
    if (this.#collecting) throw new Error('runtime_attestation_in_progress');
    const digest = createHash('sha256').update(nonce).digest('hex');
    if (this.#usedNonces.has(digest)) throw new Error('runtime_attestation_replayed_nonce');
    this.#collecting = true;
    this.rememberNonce(digest);
    return digest;
  }

  private rememberNonce(digest: string): void {
    this.#usedNonces.add(digest);
    this.#nonceOrder.push(digest);
    if (this.#nonceOrder.length > NONCE_WINDOW) {
      const expired = this.#nonceOrder.shift();
      if (expired) this.#usedNonces.delete(expired);
    }
  }
}
