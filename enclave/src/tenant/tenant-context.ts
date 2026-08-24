import type { VerifiedActivePolicySnapshotV1 } from '@folklore/inference';
import type { KeyObject } from 'node:crypto';
import type { KmsKeyringNode } from '@aws-crypto/client-node';
import { EnclaveCrypto, type SealedContentKeyringConfig } from '../crypto/esdk.js';
import type { HnswStore } from '../hnsw/index.js';
import type { Pipeline } from '../pipeline/index.js';
import { deriveIngestKeypair } from '../sealing/keygen.js';

// Thrown when a torn-down tenant's key material is touched — a removed co-tenant fails closed rather
// than decrypting with wiped material (shared-tier design §2.2 point 5). Content-free: id only.
export class TenantContextZeroizedError extends Error {
  constructor(readonly tenantId: string) {
    super(`tenant context for ${tenantId} has been zeroized`);
    this.name = 'TenantContextZeroizedError';
  }
}

// One tenant's isolated key material, index, and processing pipeline (shared-tier design §2.2).
// Every crypto/storage op takes its tenant from an explicit context like this rather than a
// process-global, and each context owns a single-CMK keyring — never a union keyring — so tenant
// A's ciphertext can never decrypt under tenant B's key material.
export class TenantContext {
  private cryptoOrNull: EnclaveCrypto | null;
  private ingestKeyOrNull: KeyObject | null;
  private keyringOrNull: KmsKeyringNode | null;
  private hnswOrNull: HnswStore | null;
  private pipelineOrNull: Pipeline | null;

  constructor(
    readonly tenantId: string,
    readonly kmsKeyId: string,
    keyring: KmsKeyringNode,
    readonly masterKey: Buffer,
    hnsw: HnswStore,
    pipeline: Pipeline,
    sealedContentKeyrings: SealedContentKeyringConfig,
    readonly sealedBlobBucket = '',
    readonly rawPayloadsBucket = '',
    readonly processedOutputsBucket = '',
    readonly deploymentId = '',
    readonly tenantDeploymentId?: string,
    private readonly activePolicySnapshotProvider?: () =>
      | VerifiedActivePolicySnapshotV1
      | undefined,
  ) {
    this.keyringOrNull = keyring;
    this.hnswOrNull = hnsw;
    this.pipelineOrNull = pipeline;
    this.cryptoOrNull = new EnclaveCrypto(keyring, sealedContentKeyrings);
    this.ingestKeyOrNull = deriveIngestKeypair(masterKey).privateKey;
  }

  get crypto(): EnclaveCrypto {
    if (!this.cryptoOrNull) throw new TenantContextZeroizedError(this.tenantId);
    return this.cryptoOrNull;
  }

  get ingestPrivateKey(): KeyObject {
    if (!this.ingestKeyOrNull) throw new TenantContextZeroizedError(this.tenantId);
    return this.ingestKeyOrNull;
  }

  get keyring(): KmsKeyringNode {
    if (!this.keyringOrNull) throw new TenantContextZeroizedError(this.tenantId);
    return this.keyringOrNull;
  }

  get hnsw(): HnswStore {
    if (!this.hnswOrNull) throw new TenantContextZeroizedError(this.tenantId);
    return this.hnswOrNull;
  }

  get pipeline(): Pipeline {
    if (!this.pipelineOrNull) throw new TenantContextZeroizedError(this.tenantId);
    return this.pipelineOrNull;
  }

  encryptStorageCanary(plaintext: Buffer, generation: number): Promise<Buffer> {
    return this.crypto.encryptStorageCanary(plaintext, this.tenantId, generation);
  }

  decryptStorageCanary(ciphertext: Buffer, generation: number): Promise<Buffer> {
    return this.crypto.decryptStorageCanary(ciphertext, this.tenantId, generation);
  }

  activePolicySnapshot(): VerifiedActivePolicySnapshotV1 | undefined {
    return this.activePolicySnapshotProvider?.();
  }

  codebaseSelectionScope(): {
    crypto: EnclaveCrypto;
    bucket: string;
    deploymentId: string;
  } {
    const deploymentId = this.tenantDeploymentId ?? this.deploymentId;
    if (!this.processedOutputsBucket || !deploymentId) {
      throw new Error('codebase_selection_context_unavailable');
    }
    return { crypto: this.crypto, bucket: this.processedOutputsBucket, deploymentId };
  }

  // §2.2 point 5 (crypto-shred boundary): teardown wipes the decrypted master secret from RAM,
  // frees the HNSW index (its decrypted embeddings are content, invariant #2), and drops every
  // key-bearing handle — crypto, ingest key, keyring, hnsw, pipeline — behind a fail-closed getter.
  // So after zeroize NO path on the context can encrypt/decrypt or expose the tenant's content, not
  // even a retained object reference; the pipeline/keyring carry their own EnclaveCrypto, so it is
  // not enough to null crypto alone. KeyObject/KMS keyring hold no zeroable plaintext (dropping is
  // all that is possible); the raw master secret is the one plaintext buffer we own, and it is filled.
  zeroize(): void {
    this.masterKey.fill(0);
    const hnsw = this.hnswOrNull;
    this.cryptoOrNull = null;
    this.ingestKeyOrNull = null;
    this.keyringOrNull = null;
    this.hnswOrNull = null;
    this.pipelineOrNull = null;
    hnsw?.free();
  }
}
