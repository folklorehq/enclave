import {
  decryptParameterForRecipient,
  decryptRecipientCiphertextWithKeyId,
} from '../sealing/seal.js';
import type { AttestedSecretDecryptorPort } from './BootManifestSecretLoader.js';

const PARAMETER_ARN = 'PARAMETER_ARN';
export const ATTESTED_DECRYPT_KEY_REQUIRED = 'attested_decrypt_key_required';
export const ATTESTED_DECRYPT_KEY_REFUSED = 'attested_decrypt_key_refused';

/** Opens a ciphertext through a Nitro Recipient; an unpinned key is allowed only for an SSM parameter, and a refused key is never returned on either path. */
export const attestedRecipientDecryptor: AttestedSecretDecryptorPort = {
  async decryptForRecipient({ ciphertext, keyId, encryptionContext, refusedKeyIds }) {
    if (keyId !== undefined) {
      const pinned = await decryptRecipientCiphertextWithKeyId(
        ciphertext,
        keyId,
        encryptionContext,
      );
      return refuseKey(pinned, refusedKeyIds);
    }
    const parameterArn = encryptionContext[PARAMETER_ARN];
    if (
      !parameterArn ||
      Object.keys(encryptionContext).length !== 1 ||
      refusedKeyIds === undefined ||
      refusedKeyIds.length === 0
    ) {
      throw new Error(ATTESTED_DECRYPT_KEY_REQUIRED);
    }
    const opened = await decryptParameterForRecipient(ciphertext, parameterArn);
    return refuseKey(opened, refusedKeyIds);
  },
};

function refuseKey(
  opened: { readonly keyId: string; readonly plaintext: Buffer },
  refusedKeyIds: readonly string[] | undefined,
): Buffer {
  if (!refusedKeyIds?.includes(opened.keyId)) return opened.plaintext;
  opened.plaintext.fill(0);
  throw new Error(ATTESTED_DECRYPT_KEY_REFUSED);
}
