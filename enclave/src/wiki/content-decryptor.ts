import type { KmsKeyringNode } from '@aws-crypto/client-node';
import type { EncryptedBlockBody, WikiBlockContentRef, WikiContentDecryptor } from '@folklore/api';
import { EnclaveCrypto } from '../crypto/esdk.js';

// ADL #12: derived knowledge is decrypted only here, inside the enclave. The API read
// path has already run the audience gate on cleartext metadata; this turns a visible
// block's ciphertext body back into its object. The AAD binds the ciphertext to its
// (org, theme, audience, type) — a body relocated to another row fails to decrypt and
// is surfaced as unreadable rather than served into the wrong page.
export class EnclaveWikiContentDecryptor implements WikiContentDecryptor {
  private readonly crypto: EnclaveCrypto;

  constructor(keyring: KmsKeyringNode) {
    this.crypto = new EnclaveCrypto(keyring);
  }

  async decryptBlockBody(
    ref: WikiBlockContentRef,
    body: EncryptedBlockBody,
  ): Promise<unknown | null> {
    try {
      const ciphertext = Buffer.from(body.ciphertext, 'base64');
      const plaintext = await this.crypto.decryptWikiBlock(ciphertext, {
        orgId: ref.orgId,
        themeId: ref.themeId,
        audienceId: ref.audienceId,
        blockType: ref.blockType,
      });
      return JSON.parse(plaintext.toString('utf8'));
    } catch {
      return null;
    }
  }
}
