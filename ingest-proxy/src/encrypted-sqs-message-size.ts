export const SQS_MAX_MESSAGE_BYTES = 256 * 1024;

const AES_GCM_AUTH_TAG_BYTES = 16;
const EPHEMERAL_PUBLIC_KEY_HEX_LENGTH = 64;
const NONCE_HEX_LENGTH = 24;

export interface EncryptedSqsMessageSizeInput {
  tenantId: string;
  source: string;
  eventType: string;
  payloadBody: string;
  messageType?: 'jira-oauth-envelope';
}

export function encryptedSqsMessageByteLength(input: EncryptedSqsMessageSizeInput): number {
  const ciphertextHexLength =
    (Buffer.byteLength(input.payloadBody, 'utf8') + AES_GCM_AUTH_TAG_BYTES) * 2;
  const body = {
    tenant_id: input.tenantId,
    source: input.source,
    ...(input.messageType ? { type: input.messageType } : {}),
    eventType: input.eventType,
    ephemeralPublicKey: '0'.repeat(EPHEMERAL_PUBLIC_KEY_HEX_LENGTH),
    nonce: '0'.repeat(NONCE_HEX_LENGTH),
    ciphertext: '0'.repeat(ciphertextHexLength),
  };
  return Buffer.byteLength(JSON.stringify(body), 'utf8');
}

export function fitsEncryptedSqsMessage(input: EncryptedSqsMessageSizeInput): boolean {
  return encryptedSqsMessageByteLength(input) <= SQS_MAX_MESSAGE_BYTES;
}
