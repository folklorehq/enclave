import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
  bootManifestSchema,
  enclaveRuntimeEvidenceSchema,
  type BootManifest,
  type BootManifestUserData,
  type EnclaveRuntimeEvidence,
  type EnclaveHealthRecord,
  type RuntimeAttestationKeyBundle,
} from '@folklore/contracts/enclave-attestation';
import {
  deriveAttestationUserData,
  encodeAttestationUserData,
  encodeRuntimeHealthSignaturePayload,
  hashNitroDocument,
  hashRuntimeAttestationKeyBundle,
} from '@folklore/nitro-attestation';
import type { NsmAttestationPort } from '../sealing/nsm.js';

const CHALLENGE_NONCE_BYTES = 32;
const NITRO_DOCUMENT_MAX_BYTES = 16 * 1024;
const NONCE_REPLAY_WINDOW_CAPACITY = 8;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

interface SessionKeyMaterial {
  privateKey: KeyObject;
  publicKey: Uint8Array;
}

interface ResponseKeyMaterial {
  privateKey: KeyObject;
  publicKey: Uint8Array;
}

export interface RuntimeAttestationReadiness {
  getReadiness():
    | RuntimeAttestationReadinessSnapshot
    | Promise<RuntimeAttestationReadinessSnapshot>;
  getIngestPublicKey?(): Uint8Array | Promise<Uint8Array>;
}

export interface RuntimeAttestationReadinessSnapshot {
  manifest: BootManifest;
  tenantAssigned: boolean;
  bootManifestVerified: boolean;
  kmsUnsealed: boolean;
  tenantApiReady: boolean;
}

export interface RuntimeAttestationKeyGenerator {
  generate(): SessionKeyMaterial;
}

export interface RuntimeAttestationClock {
  now(): Date;
}

class RuntimeAttestationFailure extends Error {}

export class RuntimeAttestationService {
  readonly #usedNonceDigests = new Set<string>();
  readonly #nonceDigestOrder: string[] = [];
  #collecting = false;
  #attested = false;
  #sessionKey: SessionKeyMaterial | undefined;
  #responseKey: ResponseKeyMaterial | undefined;
  #pinnedUserData: BootManifestUserData | undefined;

  constructor(
    private readonly readiness: RuntimeAttestationReadiness,
    private readonly nsm: NsmAttestationPort,
    private readonly clock: RuntimeAttestationClock,
    private readonly keyGenerator: RuntimeAttestationKeyGenerator = nodeKeyGenerator,
  ) {}

  async collect(nonce: Uint8Array): Promise<EnclaveRuntimeEvidence> {
    const claimed = this.claimNonce(nonce);
    this.#attested = false;
    try {
      const evidence = await this.collectEvidence(claimed.nonce);
      this.#attested = true;
      return evidence;
    } catch (error: unknown) {
      if (error instanceof RuntimeAttestationFailure) throw error;
      throw this.failure('runtime_attestation_failed');
    } finally {
      this.#collecting = false;
      this.rememberNonce(claimed.digest);
    }
  }

  sign(payload: Uint8Array): { publicKey: Uint8Array; signature: Uint8Array } {
    if (!this.#attested || !this.#sessionKey) throw this.failure('runtime_attestation_not_ready');
    if (!(payload instanceof Uint8Array) || payload.byteLength === 0) {
      throw this.failure('runtime_attestation_invalid_payload');
    }
    return {
      publicKey: Uint8Array.from(this.#sessionKey.publicKey),
      signature: Uint8Array.from(sign(null, payload, this.#sessionKey.privateKey)),
    };
  }

  private claimNonce(nonce: Uint8Array): { nonce: Uint8Array; digest: string } {
    if (!(nonce instanceof Uint8Array) || nonce.byteLength !== CHALLENGE_NONCE_BYTES) {
      throw this.failure('runtime_attestation_invalid_nonce');
    }
    if (this.#collecting) throw this.failure('runtime_attestation_in_progress');
    const nonceCopy = Uint8Array.from(nonce);
    const digest = createHash('sha256').update(nonceCopy).digest('base64');
    if (this.#usedNonceDigests.has(digest)) {
      throw this.failure('runtime_attestation_replayed_nonce');
    }
    this.#collecting = true;
    return { nonce: nonceCopy, digest };
  }

  private async collectEvidence(nonce: Uint8Array): Promise<EnclaveRuntimeEvidence> {
    const readiness = await this.readReadySnapshot();
    const sessionKey = this.getSessionKey();
    const responseKey = this.getResponseKey();
    const ingestPublicKey = await this.getIngestPublicKey(readiness.userData, readiness.snapshot);
    const runtimeKeyBundle: RuntimeAttestationKeyBundle = {
      signingPublicKey: Buffer.from(sessionKey.publicKey).toString('base64'),
      responseEncryptionPublicKey: Buffer.from(responseKey.publicKey).toString('base64'),
      ingestPublicKey: Buffer.from(ingestPublicKey).toString('base64'),
    };
    const runtimeKeyBundleHash = hashRuntimeAttestationKeyBundle(runtimeKeyBundle);
    const document = await this.nsm.attest({
      publicKey: sessionKey.publicKey,
      nonce,
      userData: encodeAttestationUserData(readiness.userData, runtimeKeyBundleHash),
    });
    if (
      !(document instanceof Uint8Array) ||
      document.byteLength === 0 ||
      document.byteLength > NITRO_DOCUMENT_MAX_BYTES
    ) {
      throw this.failure('runtime_attestation_failed');
    }
    const record = this.healthyRecord(readiness.snapshot);
    const signaturePayload = encodeRuntimeHealthSignaturePayload({
      nonce,
      documentHash: hashNitroDocument(document),
      manifestHash: readiness.userData.manifestHash,
      configurationGeneration: readiness.userData.configurationGeneration,
      record,
    });
    return enclaveRuntimeEvidenceSchema.parse({
      version: 1,
      nitroDocument: Buffer.from(document).toString('base64'),
      sessionPublicKey: Buffer.from(sessionKey.publicKey).toString('base64'),
      signedHealth: {
        version: 1,
        record,
        signature: sign(null, signaturePayload, sessionKey.privateKey).toString('base64'),
      },
      runtimeKeyBundle,
    });
  }

  private getResponseKey(): ResponseKeyMaterial {
    if (this.#responseKey) return this.#responseKey;
    const keyPair = generateKeyPairSync('x25519');
    const der = keyPair.publicKey.export({ type: 'spki', format: 'der' });
    if (!Buffer.isBuffer(der) || der.byteLength < 32) {
      throw this.failure('runtime_attestation_failed');
    }
    this.#responseKey = {
      privateKey: keyPair.privateKey,
      publicKey: Uint8Array.from(der.subarray(-32)),
    };
    return this.#responseKey;
  }

  private async getIngestPublicKey(
    userData: BootManifestUserData,
    snapshot: RuntimeAttestationReadinessSnapshot,
  ): Promise<Uint8Array> {
    const configured = await this.readiness.getIngestPublicKey?.();
    if (!(configured instanceof Uint8Array) || configured.byteLength !== 32) {
      throw this.failure('runtime_attestation_ingest_key_unavailable');
    }
    return Uint8Array.from(configured);
  }

  private async readReadySnapshot(): Promise<{
    snapshot: RuntimeAttestationReadinessSnapshot;
    userData: BootManifestUserData;
  }> {
    let snapshot: RuntimeAttestationReadinessSnapshot;
    try {
      snapshot = await this.readiness.getReadiness();
    } catch {
      throw this.failure('runtime_attestation_not_ready');
    }
    if (!this.hasAllReadyGates(snapshot)) throw this.failure('runtime_attestation_not_ready');
    const manifest = bootManifestSchema.safeParse(snapshot.manifest);
    if (!manifest.success) throw this.failure('runtime_attestation_not_ready');
    const userData = deriveAttestationUserData(manifest.data);
    if (this.#pinnedUserData === undefined) {
      this.#pinnedUserData = userData;
    } else if (!this.sameUserData(this.#pinnedUserData, userData)) {
      throw this.failure('runtime_attestation_manifest_changed');
    }
    return { snapshot, userData };
  }

  private hasAllReadyGates(
    snapshot: RuntimeAttestationReadinessSnapshot,
  ): snapshot is RuntimeAttestationReadinessSnapshot {
    return (
      snapshot !== null &&
      typeof snapshot === 'object' &&
      snapshot.tenantAssigned === true &&
      snapshot.bootManifestVerified === true &&
      snapshot.kmsUnsealed === true &&
      snapshot.tenantApiReady === true
    );
  }

  private sameUserData(left: BootManifestUserData, right: BootManifestUserData): boolean {
    return Buffer.from(encodeAttestationUserData(left)).equals(encodeAttestationUserData(right));
  }

  private getSessionKey(): SessionKeyMaterial {
    if (this.#sessionKey === undefined) this.#sessionKey = this.keyGenerator.generate();
    return this.#sessionKey;
  }

  private healthyRecord(snapshot: RuntimeAttestationReadinessSnapshot): EnclaveHealthRecord {
    const observedAt = this.clock.now();
    if (!Number.isFinite(observedAt.getTime())) throw this.failure('runtime_attestation_failed');
    return {
      version: 1,
      observedAt: observedAt.toISOString(),
      status: 'healthy',
      tenantAssigned: snapshot.tenantAssigned,
      bootManifestVerified: snapshot.bootManifestVerified,
      kmsUnsealed: snapshot.kmsUnsealed,
      tenantApiReady: snapshot.tenantApiReady,
    };
  }

  private rememberNonce(digest: string): void {
    this.#usedNonceDigests.add(digest);
    this.#nonceDigestOrder.push(digest);
    if (this.#nonceDigestOrder.length > NONCE_REPLAY_WINDOW_CAPACITY) {
      const expired = this.#nonceDigestOrder.shift();
      if (expired !== undefined) this.#usedNonceDigests.delete(expired);
    }
  }

  private failure(code: string): RuntimeAttestationFailure {
    return new RuntimeAttestationFailure(code);
  }
}

const nodeKeyGenerator: RuntimeAttestationKeyGenerator = {
  generate(): SessionKeyMaterial {
    const keyPair = generateKeyPairSync('ed25519');
    const publicKeyDer = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }));
    if (!publicKeyDer.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
      throw new Error('invalid session key');
    }
    const publicKey = publicKeyDer.subarray(ED25519_SPKI_PREFIX.length);
    if (publicKey.byteLength !== CHALLENGE_NONCE_BYTES) throw new Error('invalid session key');
    return { privateKey: keyPair.privateKey, publicKey };
  },
};
