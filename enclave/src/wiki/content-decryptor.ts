import type { EncryptedBlockBody, WikiBlockContentRef, WikiContentDecryptor } from '@folklore/api';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';

// ADL #12: derived knowledge is decrypted only here, inside the enclave. The API read
// path has already run the audience gate on cleartext metadata; this turns a visible
// block's ciphertext body back into its object. The keyring is selected per request from
// `ref.orgId` (shared-tier design §4.2), so one tenant's block is only ever opened under its
// own key. The AAD binds the ciphertext to its (org, theme, audience, type) — a body relocated
// to another row (or another tenant) fails to decrypt and is surfaced as unreadable.
export class EnclaveWikiContentDecryptor implements WikiContentDecryptor {
  constructor(private readonly resolveTenant: ResolveTenant) {}

  async decryptBlockBody(
    ref: WikiBlockContentRef,
    body: EncryptedBlockBody,
  ): Promise<unknown | null> {
    try {
      const ciphertext = Buffer.from(body.ciphertext, 'base64');
      const plaintext = await this.resolveTenant(ref.orgId).crypto.decryptWikiBlock(ciphertext, {
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
