import type {
  WikiPublicationSealer,
  WikiPublicationSnapshotRef,
  WikiPublishedBlockRef,
} from '@folklore/api';
import { canonicalJson } from '@folklore/utils';
import { errorCode, errorName } from '../logging/error-fields.js';
import { EncryptionContextMismatchError } from '../crypto/esdk.js';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';

const UNSEAL_FAILED_EVENT = 'WIKI_PUBLICATION_UNSEAL_FAILED';

export class EnclaveWikiPublicationSealer implements WikiPublicationSealer {
  constructor(private readonly resolveTenant: ResolveTenant) {}

  sealSnapshot(ref: WikiPublicationSnapshotRef, plaintext: Buffer): Promise<Buffer> {
    return this.resolveTenant(ref.orgId).crypto.encryptWikiPublicationSnapshot(plaintext, ref);
  }

  unsealSnapshot(ref: WikiPublicationSnapshotRef, ciphertext: Buffer): Promise<Buffer | null> {
    return this.tryUnseal(() =>
      this.resolveTenant(ref.orgId).crypto.decryptWikiPublicationSnapshot(ciphertext, ref),
    );
  }

  async sealBlock(ref: WikiPublishedBlockRef, body: unknown): Promise<Buffer> {
    const plaintext = Buffer.from(canonicalJson(body), 'utf8');
    try {
      return await this.resolveTenant(ref.orgId).crypto.encryptWikiPublishedBlock(plaintext, ref);
    } finally {
      plaintext.fill(0);
    }
  }

  async unsealBlock(ref: WikiPublishedBlockRef, ciphertext: Buffer): Promise<unknown | null> {
    const plaintext = await this.tryUnseal(() =>
      this.resolveTenant(ref.orgId).crypto.decryptWikiPublishedBlock(ciphertext, ref),
    );
    if (plaintext === null) return null;
    try {
      return JSON.parse(plaintext.toString('utf8')) as unknown;
    } catch (err) {
      this.logUnsealFailure(err);
      return null;
    } finally {
      plaintext.fill(0);
    }
  }

  private async tryUnseal(decrypt: () => Promise<Buffer>): Promise<Buffer | null> {
    try {
      return await decrypt();
    } catch (err) {
      this.logUnsealFailure(err);
      return null;
    }
  }

  private logUnsealFailure(err: unknown): void {
    const code = errorCode(err);
    console.warn(UNSEAL_FAILED_EVENT, {
      kind: err instanceof EncryptionContextMismatchError ? 'aad-mismatch' : 'decrypt-error',
      errorName: errorName(err),
      errorCode: code,
    });
  }
}
