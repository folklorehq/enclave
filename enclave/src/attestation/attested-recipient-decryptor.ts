import {
  decryptParameterForRecipient,
  decryptRecipientCiphertextWithKeyId,
} from '../sealing/seal.js';
import type { AttestedSecretDecryptorPort } from './BootManifestSecretLoader.js';

const PARAMETER_ARN = 'PARAMETER_ARN';
export const ATTESTED_DECRYPT_KEY_REQUIRED = 'attested_decrypt_key_required';
export const ATTESTED_DECRYPT_KEY_REFUSED = 'attested_decrypt_key_refused';

/** Opens a ciphertext through a Nitro Recipient; an unpinned key is allowed only for an SSM parameter, and never a refused one. */
export const attestedRecipientDecryptor: AttestedSecretDecryptorPort = {
  async decryptForRecipient({ ciphertext, keyId, encryptionContext, refusedKeyIds }) {
    if (keyId !== undefined) {
      return (await decryptRecipientCiphertextWithKeyId(ciphertext, keyId, encryptionContext))
        .plaintext;
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
    if (refusedKeyIds.includes(opened.keyId)) {
      opened.plaintext.fill(0);
      throw new Error(ATTESTED_DECRYPT_KEY_REFUSED);
    }
    return opened.plaintext;
  },
};
