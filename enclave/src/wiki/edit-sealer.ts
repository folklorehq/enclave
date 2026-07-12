import type { KmsKeyringNode } from '@aws-crypto/client-node';
import type { WikiEditSealer, WikiEditSealRef } from '@folklore/api';
import { EnclaveCrypto } from '../crypto/esdk.js';

// ADL #12/#45: the before/after prose of a mined edit is sealed to the same key as wiki blocks,
// bound to (org, theme, audience, blockType) in a distinct `edit-delta:` namespace so a delta
// ciphertext can never be served through the block read path. Sealed + unsealed only in-enclave.
const EDIT_DELTA_PREFIX = 'edit-delta:';

export class EnclaveWikiEditSealer implements WikiEditSealer {
  private readonly crypto: EnclaveCrypto;

  constructor(keyring: KmsKeyringNode) {
    this.crypto = new EnclaveCrypto(keyring);
  }

  seal(ref: WikiEditSealRef, plaintext: Buffer): Promise<Buffer> {
    return this.crypto.encryptWikiBlock(plaintext, this.blockRef(ref));
  }

  async unseal(ref: WikiEditSealRef, ciphertext: Buffer): Promise<Buffer | null> {
    try {
      return await this.crypto.decryptWikiBlock(ciphertext, this.blockRef(ref));
    } catch {
      return null;
    }
  }

  private blockRef(ref: WikiEditSealRef): {
    orgId: string;
    themeId: string;
    audienceId: string | null;
    blockType: string;
  } {
    return {
      orgId: ref.orgId,
      themeId: ref.themeId,
      audienceId: ref.audienceId,
      blockType: `${EDIT_DELTA_PREFIX}${ref.blockType}`,
    };
  }
}
