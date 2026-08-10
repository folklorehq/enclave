import type {
  AttestationBootCheckpoint,
  AttestationBootCheckpointStore,
} from './AttestationBootState.js';

export class InMemoryAttestationBootCheckpointStore implements AttestationBootCheckpointStore {
  private checkpoint: AttestationBootCheckpoint | null = null;

  async read(): Promise<AttestationBootCheckpoint | null> {
    return this.checkpoint === null ? null : Object.freeze({ ...this.checkpoint });
  }

  async write(checkpoint: AttestationBootCheckpoint): Promise<void> {
    this.checkpoint = Object.freeze({ ...checkpoint });
  }
}
