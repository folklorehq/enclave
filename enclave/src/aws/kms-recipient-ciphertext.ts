import { constants, createDecipheriv, privateDecrypt, type KeyObject } from 'node:crypto';
import * as asn1js from 'asn1js';
import { ContentInfo, EnvelopedData, KeyTransRecipientInfo } from 'pkijs';

const ENVELOPED_DATA_OID = '1.2.840.113549.1.7.3';
const DATA_OID = '1.2.840.113549.1.7.1';
const RSAES_OAEP_OID = '1.2.840.113549.1.1.7';
const AES_256_CBC_OID = '2.16.840.1.101.3.4.1.42';
const AES_256_KEY_BYTES = 32;
const AES_CBC_IV_BYTES = 16;
const RECIPIENT_OUTPUT_INVALID = 'recipient_kms_output_invalid';

interface RecipientEnvelope {
  encryptedKey: Buffer;
  iv: Buffer;
  encryptedContent: Buffer;
}

// KMS answers a Recipient request with CMS EnvelopedData (RFC 5652), not a bare RSA-OAEP block.
export function openKmsRecipientCiphertext(
  privateKey: KeyObject,
  ciphertextForRecipient: Uint8Array,
): Buffer {
  let contentKey: Buffer | undefined;
  try {
    const envelope = parseRecipientEnvelope(ciphertextForRecipient);
    contentKey = privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      envelope.encryptedKey,
    );
    if (contentKey.length !== AES_256_KEY_BYTES) throw new Error(RECIPIENT_OUTPUT_INVALID);
    const decipher = createDecipheriv('aes-256-cbc', contentKey, envelope.iv);
    return Buffer.concat([decipher.update(envelope.encryptedContent), decipher.final()]);
  } catch {
    throw new Error(RECIPIENT_OUTPUT_INVALID);
  } finally {
    contentKey?.fill(0);
  }
}

function parseRecipientEnvelope(ber: Uint8Array): RecipientEnvelope {
  const parsed = asn1js.fromBER(ber);
  if (parsed.offset !== ber.byteLength) throw new Error(RECIPIENT_OUTPUT_INVALID);
  const contentInfo = new ContentInfo({ schema: parsed.result });
  if (contentInfo.contentType !== ENVELOPED_DATA_OID) throw new Error(RECIPIENT_OUTPUT_INVALID);
  const envelopedData = new EnvelopedData({ schema: contentInfo.content });
  const [recipient, ...others] = envelopedData.recipientInfos;
  const keyTransport = recipient?.value;
  if (
    others.length > 0 ||
    !(keyTransport instanceof KeyTransRecipientInfo) ||
    keyTransport.keyEncryptionAlgorithm.algorithmId !== RSAES_OAEP_OID
  ) {
    throw new Error(RECIPIENT_OUTPUT_INVALID);
  }
  const contentInfoBlock = envelopedData.encryptedContentInfo;
  const iv = contentInfoBlock.contentEncryptionAlgorithm.algorithmParams;
  if (
    contentInfoBlock.contentType !== DATA_OID ||
    contentInfoBlock.contentEncryptionAlgorithm.algorithmId !== AES_256_CBC_OID ||
    !(iv instanceof asn1js.OctetString) ||
    iv.valueBlock.valueHexView.byteLength !== AES_CBC_IV_BYTES
  ) {
    throw new Error(RECIPIENT_OUTPUT_INVALID);
  }
  return {
    encryptedKey: Buffer.from(keyTransport.encryptedKey.valueBlock.valueHexView),
    iv: Buffer.from(iv.valueBlock.valueHexView),
    encryptedContent: Buffer.from(contentInfoBlock.getEncryptedContent()),
  };
}
