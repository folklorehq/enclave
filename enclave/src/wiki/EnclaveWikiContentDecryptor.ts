import {
  isLegacyEncryptedBlockBody,
  type EncryptedBlockBody,
  type TeamOnboardingBlockContentRef,
  type TeamOnboardingContentDecryptor,
  type WikiBlockContentRef,
  type WikiContentDecryptor,
} from '@folklore/api';
import type { EncryptedBody } from '@folklore/contracts/enclave';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';

// derived knowledge is decrypted only here, inside the enclave. The API read
// path has already run the audience gate on cleartext metadata; this turns a visible
// block's ciphertext body back into its object. The keyring is selected per request from
// `ref.orgId` (shared-tier design §4.2), so one tenant's block is only ever opened under its
// own key. The AAD binds the ciphertext to its (org, theme, audience, type) — a body relocated
// to another row (or another tenant) fails to decrypt and is surfaced as unreadable.
export class EnclaveWikiContentDecryptor
  implements WikiContentDecryptor, TeamOnboardingContentDecryptor
{
  constructor(private readonly resolveTenant: ResolveTenant) {}

  async decryptBlockBody(
    ref: WikiBlockContentRef,
    body: EncryptedBlockBody,
  ): Promise<unknown | null> {
    try {
      const crypto = this.resolveTenant(ref.orgId).crypto;
      const plaintext = isLegacyEncryptedBlockBody(body)
        ? await crypto.decryptWikiBlock(Buffer.from(body.ciphertext, 'base64'), ref)
        : await crypto.openWikiBlockEnvelope(body, ref);
      return JSON.parse(plaintext.toString('utf8'));
    } catch {
      return null;
    }
  }

  async decryptTeamOnboardingBlockBody(
    ref: TeamOnboardingBlockContentRef,
    body: EncryptedBody,
  ): Promise<unknown | null> {
    try {
      const plaintext = await this.resolveTenant(ref.orgId).crypto.openTeamOnboardingBlockEnvelope(
        body,
        ref,
      );
      return JSON.parse(plaintext.toString('utf8'));
    } catch {
      return null;
    }
  }
}
