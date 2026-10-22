import {
  DecryptCommand,
  type DecryptCommandInput,
  type DecryptCommandOutput,
  type KMS,
} from '@aws-sdk/client-kms';

export type RecipientDecrypt = (input: {
  ciphertext: Buffer;
  keyId: string;
  encryptionContext: Record<string, string>;
}) => Promise<{ keyId: string; plaintext: Buffer }>;

export const RECIPIENT_KMS_SEND_DECRYPT_REFUSED = 'recipient_kms_send_decrypt_refused';

const DECRYPT_COMMAND_NAME = 'DecryptCommand';

export function createRecipientKmsClient(
  client: KMS,
  decryptRecipient: RecipientDecrypt,
  expectedKeyId?: string,
): KMS {
  const decrypt = async (input: DecryptCommandInput): Promise<DecryptCommandOutput> => {
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
    return { KeyId: output.keyId, Plaintext: output.plaintext, $metadata: {} };
  };

  return new Proxy(client as object, {
    get(target, property, receiver) {
      if (property === 'decrypt') return decrypt;
      if (property === 'send')
        return (command: object, ...rest: unknown[]) => sendGuarded(client, command, rest);
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(receiver) : value;
    },
  }) as KMS;
}

// Decrypt must go through the attested recipient path, never the role's plain command.
function sendGuarded(client: KMS, command: object, rest: unknown[]): Promise<unknown> {
  if (isDecryptCommand(command))
    return Promise.reject(new Error(RECIPIENT_KMS_SEND_DECRYPT_REFUSED));
  const send = client.send.bind(client) as (
    command: object,
    ...rest: unknown[]
  ) => Promise<unknown>;
  return send(command, ...rest);
}

function isDecryptCommand(command: object): boolean {
  return command instanceof DecryptCommand || command.constructor?.name === DECRYPT_COMMAND_NAME;
}
