import { parseNitroCoseSign1 } from './nitro-cose-sign1.js';
import { parseNitroDocumentPayload } from './nitro-document-payload.js';

export function extractRuntimeAttestationNonce(documentBase64: string): Uint8Array {
  const document = Buffer.from(documentBase64, 'base64');
  const cose = parseNitroCoseSign1(document);
  return parseNitroDocumentPayload(cose.payload).nonce;
}
