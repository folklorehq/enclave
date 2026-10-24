// KMS recipient attestation: response is encrypted to our ephemeral key — plaintext never leaves this heap.
import {
  KMSClient,
  DecryptCommand,
  EncryptCommand,
  GenerateDataKeyCommand,
  type GenerateDataKeyCommandOutput,
} from '@aws-sdk/client-kms';
import { generateKeyPair, type KeyObject } from 'crypto';
import { promisify } from 'util';
import { awsClientTransport } from '../aws/aws-transport.js';
import { openKmsRecipientCiphertext } from '../aws/kms-recipient-ciphertext.js';
import { getAttestationDoc } from './nsm.js';
import { assertDevKmsStubAllowed } from './dev-kms-stub-guard.js';
import { logger } from '../logger.js';
import { AttestedRecipients, type AttestedRecipient } from './AttestedRecipients.js';
import { RecipientKeyCache, type RecipientKeyPair } from './RecipientKeyCache.js';

const REGION = process.env['AWS_REGION'] ?? 'us-east-1';
const MASTER_KEY_PURPOSE = 'master-key';
const MASTER_KEY_VERSION = '2';
const MASTER_KEY_BYTES = 32;
const EPHEMERAL_RSA_BITS = 2048;
// One compromised key exposes only this window of KMS responses, since every request carries its own attested document.
const RECIPIENT_KEY_TTL_MS = 60_000;
const RECIPIENT_KEY_REFRESH_LEAD_MS = 15_000;
const RECIPIENT_OUTPUT_INVALID = 'recipient_kms_output_invalid';

export interface MintedMasterKey {
  masterKey: Buffer;
  sealedBlob: Buffer;
}

function masterKeyContext(tenantId: string): Record<string, string> {
  return { purpose: MASTER_KEY_PURPOSE, version: MASTER_KEY_VERSION, tenantId };
}

let sharedKmsClient: KMSClient | undefined;

function kmsClient(): KMSClient {
  sharedKmsClient ??= new KMSClient({
    region: REGION,
    ...awsClientTransport(),
  });
  return sharedKmsClient;
}

const generateKeyPairAsync = promisify(generateKeyPair);

async function generateRecipientKeyPair(): Promise<RecipientKeyPair> {
  const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
    modulusLength: EPHEMERAL_RSA_BITS,
  });
  return {
    publicKeyDer: Buffer.from(publicKey.export({ type: 'spki', format: 'der' })),
    privateKey,
  };
}

// The key rides in the attestation document, so KMS encrypts its answer to this enclave alone.
export const attestedRecipients = new AttestedRecipients(
  new RecipientKeyCache({
    generate: generateRecipientKeyPair,
    ttlMs: RECIPIENT_KEY_TTL_MS,
    refreshLeadMs: RECIPIENT_KEY_REFRESH_LEAD_MS,
    logger,
  }),
  getAttestationDoc,
);

const freshRecipients = new AttestedRecipients(
  { acquire: generateRecipientKeyPair },
  getAttestationDoc,
);

// KMS chooses the key and releases it only to the attested enclave, so no other caller can pick it.
export async function mintMasterKey(kmsKeyId: string, tenantId: string): Promise<MintedMasterKey> {
  return freshRecipients.withRecipient(async ({ recipient, privateKey }) => {
    const response = await kmsClient().send(
      new GenerateDataKeyCommand({
        KeyId: kmsKeyId,
        NumberOfBytes: MASTER_KEY_BYTES,
        EncryptionContext: masterKeyContext(tenantId),
        Recipient: recipient,
      }),
    );
    return openMintedMasterKey(response, kmsKeyId, privateKey);
  });
}

function openMintedMasterKey(
  response: GenerateDataKeyCommandOutput,
  kmsKeyId: string,
  privateKey: KeyObject,
): MintedMasterKey {
  if (
    (response.Plaintext !== undefined && response.Plaintext.byteLength > 0) ||
    !response.CiphertextForRecipient?.byteLength ||
    !response.CiphertextBlob?.byteLength ||
    response.KeyId !== kmsKeyId
  ) {
    throw new Error(RECIPIENT_OUTPUT_INVALID);
  }
  const masterKey = openKmsRecipientCiphertext(privateKey, response.CiphertextForRecipient);
  if (masterKey.length !== MASTER_KEY_BYTES) {
    masterKey.fill(0);
    throw new Error(RECIPIENT_OUTPUT_INVALID);
  }
  return { masterKey, sealedBlob: Buffer.from(response.CiphertextBlob) };
}

export async function sealKmsPayload(
  plaintext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  const response = await kmsClient().send(
    new EncryptCommand({
      KeyId: kmsKeyId,
      Plaintext: plaintext,
      EncryptionContext: encryptionContext,
    }),
  );
  if (!response.CiphertextBlob) throw new Error(RECIPIENT_OUTPUT_INVALID);
  return Buffer.from(response.CiphertextBlob);
}

export async function unsealMasterKey(
  ciphertext: Buffer,
  kmsKeyId: string,
  tenantId: string,
): Promise<Buffer> {
  return decryptWithContext(ciphertext, kmsKeyId, masterKeyContext(tenantId));
}

async function decryptWithContext(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  return (await decryptWithContextAndKeyId(ciphertext, kmsKeyId, encryptionContext)).plaintext;
}

export async function decryptRecipientCiphertextWithKeyId(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<{ keyId: string; plaintext: Buffer }> {
  return decryptWithContextAndKeyId(ciphertext, kmsKeyId, encryptionContext);
}

// An SSM SecureString names its own key; SSM bound it to the parameter ARN when it encrypted.
export async function decryptParameterForRecipient(
  ciphertext: Buffer,
  parameterArn: string,
): Promise<{ keyId: string; plaintext: Buffer }> {
  return decryptWithContextAndKeyId(ciphertext, undefined, { PARAMETER_ARN: parameterArn });
}

async function decryptWithContextAndKeyId(
  ciphertext: Buffer,
  kmsKeyId: string | undefined,
  encryptionContext: Record<string, string>,
): Promise<{ keyId: string; plaintext: Buffer }> {
  // Dev-only: localstack KMS cannot perform the Nitro Recipient decrypt (it returns no
  // CiphertextForRecipient), so a plain KMS Decrypt stands in for every seal.ts decrypt (content
  // keyring, boot-manifest secrets, provider-refresh secrets, boot checkpoints, runtime-DB creds).
  // Fail-closed exactly like devMasterKeySealers: the shared guard throws outside development/test,
  // and the production EIF additionally pins NODE_ENV=production in entrypoint.sh AND denies this
  // flag from the parent env (aws-transport/egress-allowlist tests), so it can never activate there.
  // The AAD (EncryptionContext) is forwarded unchanged, so tenant/purpose binding is preserved.
  if (process.env['ENCLAVE_DEV_KMS_STUB'] === 'true') {
    assertDevKmsStubAllowed(process.env['NODE_ENV'] ?? '');
    const devResponse = await kmsClient().send(
      new DecryptCommand({
        ...(kmsKeyId === undefined ? {} : { KeyId: kmsKeyId }),
        CiphertextBlob: ciphertext,
        EncryptionContext: encryptionContext,
      }),
    );
    if (!devResponse.KeyId || !devResponse.Plaintext) {
      throw new Error(RECIPIENT_OUTPUT_INVALID);
    }
    return { keyId: devResponse.KeyId, plaintext: Buffer.from(devResponse.Plaintext) };
  }
  return attestedRecipients.withRecipient((attested) =>
    decryptWithRecipient(attested, ciphertext, kmsKeyId, encryptionContext),
  );
}

async function decryptWithRecipient(
  { recipient, privateKey }: AttestedRecipient,
  ciphertext: Buffer,
  kmsKeyId: string | undefined,
  encryptionContext: Record<string, string>,
): Promise<{ keyId: string; plaintext: Buffer }> {
  const response = await kmsClient().send(
    new DecryptCommand({
      ...(kmsKeyId === undefined ? {} : { KeyId: kmsKeyId }),
      CiphertextBlob: ciphertext,
      EncryptionContext: encryptionContext,
      Recipient: recipient,
    }),
  );

  if (!response.KeyId || !response.CiphertextForRecipient)
    throw new Error(RECIPIENT_OUTPUT_INVALID);
  return {
    keyId: response.KeyId,
    plaintext: openKmsRecipientCiphertext(privateKey, response.CiphertextForRecipient),
  };
}

export async function decryptRecipientCiphertext(
  ciphertext: Buffer,
  kmsKeyId: string,
  encryptionContext: Record<string, string>,
): Promise<Buffer> {
  return decryptWithContext(ciphertext, kmsKeyId, encryptionContext);
}
