import { verify, type KeyObject } from 'node:crypto';

import { NitroAttestationError } from './failures.js';
import { encodeNitroCoseSignatureStructure, type NitroCoseSign1 } from './nitro-cose-sign1.js';

export function verifyNitroCoseSignature(cose: NitroCoseSign1, leafKey: KeyObject): void {
  const isValid = verify(
    'sha384',
    encodeNitroCoseSignatureStructure(cose),
    { key: leafKey, dsaEncoding: 'ieee-p1363' },
    cose.signature,
  );
  if (!isValid) {
    throw new NitroAttestationError('invalid_document_signature');
  }
}
