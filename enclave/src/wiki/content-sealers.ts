import type { KmsKeyringNode } from '@aws-crypto/client-node';
import type {
  WikiCommentSealRef,
  WikiCommentSealer,
  WikiFeedbackSealRef,
  WikiFeedbackSealer,
  WikiSnapshotSealRef,
  WikiSnapshotSealer,
} from '@folklore/api';
import { EnclaveCrypto, EncryptionContextMismatchError } from '../crypto/esdk.js';

const UNSEAL_FAILED_EVENT = 'WIKI_UNSEAL_FAILED';

// ADL #12: human-authored wiki prose at rest (live-collab snapshots, comments, feedback
// corrections) is sealed to the same key as wiki blocks and unsealed only in-enclave. A relocated
// or legacy blob fails the AAD check and surfaces as null so the caller can reject it loudly.
abstract class EnclaveSealerBase {
  protected readonly crypto: EnclaveCrypto;

  constructor(keyring: KmsKeyringNode) {
    this.crypto = new EnclaveCrypto(keyring);
  }

  protected async tryUnseal(decrypt: () => Promise<Buffer>): Promise<Buffer | null> {
    try {
      return await decrypt();
    } catch (err) {
      this.logUnsealFailure(err);
      return null;
    }
  }

  // Content-free (ADL #12/#18): the error class/code only — never the message or plaintext — lets
  // operators tell a genuine AAD-mismatch integrity event from a transient/infra (e.g. KMS) blip.
  private logUnsealFailure(err: unknown): void {
    const integrity = err instanceof EncryptionContextMismatchError;
    console.warn(UNSEAL_FAILED_EVENT, {
      kind: integrity ? 'aad-mismatch' : 'decrypt-error',
      errorName: err instanceof Error ? err.name : typeof err,
      errorCode: this.errorCode(err),
    });
  }

  private errorCode(err: unknown): string | undefined {
    if (typeof err !== 'object' || err === null || !('code' in err)) return undefined;
    const code = (err as { code: unknown }).code;
    return typeof code === 'string' ? code : undefined;
  }
}

export class EnclaveWikiSnapshotSealer extends EnclaveSealerBase implements WikiSnapshotSealer {
  seal(ref: WikiSnapshotSealRef, plaintext: Buffer): Promise<Buffer> {
    return this.crypto.encryptCollabSnapshot(plaintext, ref);
  }

  unseal(ref: WikiSnapshotSealRef, ciphertext: Buffer): Promise<Buffer | null> {
    return this.tryUnseal(() => this.crypto.decryptCollabSnapshot(ciphertext, ref));
  }
}

export class EnclaveWikiCommentSealer extends EnclaveSealerBase implements WikiCommentSealer {
  seal(ref: WikiCommentSealRef, plaintext: Buffer): Promise<Buffer> {
    return this.crypto.encryptWikiComment(plaintext, ref);
  }

  unseal(ref: WikiCommentSealRef, ciphertext: Buffer): Promise<Buffer | null> {
    return this.tryUnseal(() => this.crypto.decryptWikiComment(ciphertext, ref));
  }
}

export class EnclaveWikiFeedbackSealer extends EnclaveSealerBase implements WikiFeedbackSealer {
  seal(ref: WikiFeedbackSealRef, plaintext: Buffer): Promise<Buffer> {
    return this.crypto.encryptWikiFeedback(plaintext, ref);
  }

  unseal(ref: WikiFeedbackSealRef, ciphertext: Buffer): Promise<Buffer | null> {
    return this.tryUnseal(() => this.crypto.decryptWikiFeedback(ciphertext, ref));
  }
}
