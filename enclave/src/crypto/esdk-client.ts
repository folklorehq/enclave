import {
  AlgorithmSuiteIdentifier,
  buildClient,
  CommitmentPolicy,
  type KeyringNode,
  type MessageHeader,
} from '@aws-crypto/client-node';

export const ESDK_COMMITMENT_POLICY = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
export const ESDK_ALGORITHM_SUITE =
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
// Every enclave keyring wraps under a single key, so a message with more data keys is not ours.
export const ESDK_MAX_ENCRYPTED_DATA_KEYS = 1;
// Matches every existing ciphertext; frames of 16 KiB or more have decrypted to truncated plaintext.
export const ESDK_FRAME_LENGTH = 4096;

const client = buildClient({
  commitmentPolicy: ESDK_COMMITMENT_POLICY,
  maxEncryptedDataKeys: ESDK_MAX_ENCRYPTED_DATA_KEYS,
});

export async function esdkEncrypt(
  keyring: KeyringNode,
  plaintext: Buffer,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  const { result } = await client.encrypt(keyring, plaintext, {
    encryptionContext,
    suiteId: ESDK_ALGORITHM_SUITE,
    frameLength: ESDK_FRAME_LENGTH,
  });
  return result;
}

export async function esdkDecrypt(
  keyring: KeyringNode,
  ciphertext: Buffer,
): Promise<{ plaintext: Buffer; messageHeader: MessageHeader }> {
  return client.decrypt(keyring, ciphertext);
}
