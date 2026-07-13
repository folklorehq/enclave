import type { KeyObject } from 'node:crypto';
import type { KmsKeyringNode } from '@aws-crypto/client-node';
import { EnclaveCrypto } from '../crypto/esdk.js';
import type { HnswStore } from '../hnsw/index.js';
import type { Pipeline } from '../pipeline/index.js';
import { deriveIngestKeypair } from '../sealing/keygen.js';

// One tenant's isolated key material, index, and processing pipeline (shared-tier design §2.2).
// Every crypto/storage op takes its tenant from an explicit context like this rather than a
// process-global, and each context owns a single-CMK keyring — never a union keyring — so tenant
// A's ciphertext can never decrypt under tenant B's key material.
export class TenantContext {
  readonly crypto: EnclaveCrypto;
  readonly ingestPrivateKey: KeyObject;

  constructor(
    readonly tenantId: string,
    readonly kmsKeyId: string,
    readonly keyring: KmsKeyringNode,
    readonly masterKey: Buffer,
    readonly hnsw: HnswStore,
    readonly pipeline: Pipeline,
  ) {
    this.crypto = new EnclaveCrypto(keyring);
    this.ingestPrivateKey = deriveIngestKeypair(masterKey).privateKey;
  }
}
