import { NITRO_ATTESTATION_DOCUMENT_MAX_BYTES } from '@folklore/contracts/enclave-attestation';
import { decode, encode } from 'cborg';

import { NitroAttestationError } from './failures.js';

const PROTECTED_ES384_HEADER = Uint8Array.from([0xa1, 0x01, 0x38, 0x22]);
const ES384_P1363_SIGNATURE_BYTES = 96;
const COSE_SIGN1_TAG = 18;

const decodeOptions = {
  strict: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowBigInt: false,
  tags: {
    [COSE_SIGN1_TAG]: (decodeTagged: () => unknown): TaggedValue => ({
      tag: COSE_SIGN1_TAG,
      value: decodeTagged(),
    }),
  },
} as const;

interface TaggedValue {
  tag: number;
  value: unknown;
}

function hasFixedProtectedHeader(value: unknown): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.length === PROTECTED_ES384_HEADER.length &&
    value.every((byte, index) => byte === PROTECTED_ES384_HEADER[index])
  );
}

export interface NitroCoseSign1 {
  protectedHeader: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
}

function decodeCose(document: Uint8Array): unknown {
  try {
    return decode(document, decodeOptions) as unknown;
  } catch {
    throw new NitroAttestationError('malformed_document');
  }
}

// AWS NSM emits untagged COSE_Sign1, and the tag is outside the Sig_structure the signature covers.
function coseSign1Values(decoded: unknown): unknown[] {
  if (Array.isArray(decoded)) return decoded as unknown[];
  const tagged = decoded as Partial<TaggedValue> | null;
  if (tagged?.tag === COSE_SIGN1_TAG && Array.isArray(tagged.value)) {
    return tagged.value as unknown[];
  }
  throw new NitroAttestationError('invalid_cose_profile');
}

export function parseNitroCoseSign1(document: Uint8Array): NitroCoseSign1 {
  if (document.byteLength === 0 || document.byteLength > NITRO_ATTESTATION_DOCUMENT_MAX_BYTES) {
    throw new NitroAttestationError('malformed_document');
  }
  const values = coseSign1Values(decodeCose(document));
  if (values.length !== 4) {
    throw new NitroAttestationError('invalid_cose_profile');
  }
  if (!hasFixedProtectedHeader(values[0])) {
    throw new NitroAttestationError('invalid_cose_profile');
  }
  if (!(values[1] instanceof Map) || values[1].size !== 0) {
    throw new NitroAttestationError('invalid_cose_profile');
  }
  if (!(values[2] instanceof Uint8Array)) {
    throw new NitroAttestationError('invalid_cose_profile');
  }
  if (!(values[3] instanceof Uint8Array) || values[3].byteLength !== ES384_P1363_SIGNATURE_BYTES) {
    throw new NitroAttestationError('invalid_cose_profile');
  }
  return {
    protectedHeader: values[0] as Uint8Array,
    payload: values[2] as Uint8Array,
    signature: values[3] as Uint8Array,
  };
}

export function encodeNitroCoseSignatureStructure(cose: NitroCoseSign1): Uint8Array {
  return encode(['Signature1', cose.protectedHeader, new Uint8Array(), cose.payload]);
}
