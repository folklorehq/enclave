import { timingSafeEqual } from 'node:crypto';

export interface StorageCanaryStore {
  put(bucket: string, key: string, body: Buffer): Promise<void>;
  get(bucket: string, key: string): Promise<Buffer>;
}

export interface StorageCanaryTenant {
  tenantId: string;
  processedOutputsBucket: string;
  encryptStorageCanary(plaintext: Buffer, generation: number): Promise<Buffer>;
  decryptStorageCanary(ciphertext: Buffer, generation: number): Promise<Buffer>;
}

export class StorageCanaryProof {
  constructor(private readonly store: StorageCanaryStore) {}

  async prove(tenant: StorageCanaryTenant, generation: number): Promise<string> {
    const plaintext = Buffer.from(
      `folklore.storage-canary.v1\u0000${tenant.tenantId}\u0000${generation}`,
      'utf8',
    );
    const ciphertext = await tenant.encryptStorageCanary(plaintext, generation);
    const key = `storage-canary/v1/${tenant.tenantId}/${generation}`;
    await this.store.put(tenant.processedOutputsBucket, key, ciphertext);
    const stored = await this.store.get(tenant.processedOutputsBucket, key);
    const roundTrip = await tenant.decryptStorageCanary(stored, generation);
    if (roundTrip.length !== plaintext.length || !timingSafeEqual(roundTrip, plaintext)) {
      throw new Error('storage_canary_round_trip_failed');
    }
    return tenant.tenantId;
  }
}
