import AWS from 'aws-sdk';

export type RecipientDecrypt = (input: {
  ciphertext: Buffer;
  keyId: string;
  encryptionContext: Record<string, string>;
}) => Promise<{ keyId: string; plaintext: Buffer }>;

export function createRecipientKmsClient(
  client: AWS.KMS,
  decryptRecipient: RecipientDecrypt,
  expectedKeyId?: string,
): AWS.KMS {
  return new Proxy(client as object, {
    get(target, property, receiver) {
      if (property === 'decrypt') {
        return (input: AWS.KMS.DecryptRequest) =>
          ({
            promise: async () => {
              const keyId = input.KeyId ?? expectedKeyId;
              if (!keyId || !(input.CiphertextBlob instanceof Uint8Array)) {
                throw new Error('recipient_kms_decrypt_input_invalid');
              }
              const output = await decryptRecipient({
                ciphertext: Buffer.from(input.CiphertextBlob),
                keyId,
                encryptionContext: input.EncryptionContext ?? {},
              });
              if (output.keyId !== keyId) throw new Error('recipient_kms_key_mismatch');
              return {
                KeyId: output.keyId,
                Plaintext: output.plaintext,
              } as AWS.KMS.DecryptResponse;
            },
          }) as unknown as AWS.Request<AWS.KMS.DecryptResponse, AWS.AWSError>;
      }
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as AWS.KMS;
}
