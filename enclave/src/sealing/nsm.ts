import { createRequire } from 'node:module';
import { decode } from 'cborg';

const require = createRequire(import.meta.url);
// Matches the NSM driver's NSM_REQUEST_MAX_SIZE; each field also carries its own cap below.
export const REQUEST_MAX_BYTES = 0x1000;
export const USER_DATA_MAX_BYTES = 512;
const PUBLIC_KEY_MAX_BYTES = 512;
const RESPONSE_MAX_BYTES = 16 * 1024;
const NONCE_BYTES = 32;

const decodeOptions = {
  strict: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowBigInt: false,
} as const;

export interface NsmAttestationRequest {
  publicKey?: Uint8Array;
  nonce?: Uint8Array;
  userData?: Uint8Array;
}

export interface NsmIoctlPort {
  call(request: Uint8Array): Uint8Array;
}

export interface NsmAttestationPort {
  attest(request: NsmAttestationRequest): Uint8Array | Promise<Uint8Array>;
}

export function createNsmAttestationPort(ioctl: NsmIoctlPort): NsmAttestationPort {
  return {
    attest(request) {
      const encoded = encodeAttestationRequest(request);
      let response: Uint8Array;
      try {
        response = ioctl.call(encoded);
      } catch {
        throw new Error('nsm_unavailable');
      }
      return decodeNsmResponse(response, 'Attestation', 'document');
    },
  };
}

export function getAttestationDoc(input: Uint8Array | NsmAttestationRequest): Buffer {
  const request = normalizeAttestationRequest(input);
  const document = createNsmAttestationPort(nativeIoctlPort).attest(request);
  if (document instanceof Promise) throw new Error('nsm_unavailable');
  return Buffer.from(document);
}

function normalizeAttestationRequest(
  input: Uint8Array | NsmAttestationRequest,
): NsmAttestationRequest {
  if (input instanceof Uint8Array) return { publicKey: input };
  return input;
}

function encodeAttestationRequest(request: NsmAttestationRequest): Uint8Array {
  const publicKey = validateOptionalPublicKey(request.publicKey);
  const nonce = validateOptionalNonce(request.nonce);
  const userData = validateOptionalUserData(request.userData);
  const encoded = Uint8Array.from([
    0xa1,
    0x6b,
    ...Buffer.from('Attestation'),
    0xa3,
    0x69,
    ...Buffer.from('user_data'),
    ...encodeOptionalByteString(userData),
    0x65,
    ...Buffer.from('nonce'),
    ...encodeOptionalByteString(nonce),
    0x6a,
    ...Buffer.from('public_key'),
    ...encodeOptionalByteString(publicKey),
  ]);
  if (encoded.byteLength > REQUEST_MAX_BYTES) throw new Error('nsm_invalid_request');
  return encoded;
}

function validateOptionalNonce(value: Uint8Array | undefined): Uint8Array | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof Uint8Array) || value.byteLength !== NONCE_BYTES) {
    throw new Error('nsm_invalid_request');
  }
  return value;
}

function validateOptionalUserData(value: Uint8Array | undefined): Uint8Array | undefined {
  if (value === undefined) return undefined;
  return validateByteString(value, USER_DATA_MAX_BYTES);
}

function validateOptionalPublicKey(value: Uint8Array | undefined): Uint8Array | undefined {
  if (value === undefined) return undefined;
  return validateByteString(value, PUBLIC_KEY_MAX_BYTES);
}

function validateByteString(value: unknown, maxBytes: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > maxBytes) {
    throw new Error('nsm_invalid_request');
  }
  return value;
}

function encodeOptionalByteString(value: Uint8Array | undefined): number[] {
  return value === undefined ? [0xf6] : encodeByteString(value);
}

function encodeByteString(value: Uint8Array): number[] {
  if (value.byteLength < 24) return [0x40 + value.byteLength, ...value];
  if (value.byteLength <= 0xff) return [0x58, value.byteLength, ...value];
  return [0x59, value.byteLength >> 8, value.byteLength & 0xff, ...value];
}

function decodeNsmResponse(response: unknown, operation: string, field: string): Uint8Array {
  if (
    !(response instanceof Uint8Array) ||
    response.byteLength === 0 ||
    response.byteLength > RESPONSE_MAX_BYTES
  ) {
    throw new Error('nsm_invalid_response');
  }
  try {
    const outer = decode(response, decodeOptions);
    if (!(outer instanceof Map) || outer.size !== 1 || outer.get(operation) === undefined) {
      throw new Error('invalid');
    }
    const inner = outer.get(operation);
    if (!(inner instanceof Map) || inner.size !== 1) throw new Error('invalid');
    const value = inner.get(field);
    if (
      !(value instanceof Uint8Array) ||
      value.byteLength === 0 ||
      value.byteLength > RESPONSE_MAX_BYTES
    ) {
      throw new Error('invalid');
    }
    return value;
  } catch {
    throw new Error('nsm_invalid_response');
  }
}

const nativeIoctlPort: NsmIoctlPort = {
  call(request) {
    return callNative(request);
  },
};

function callNative(request: Uint8Array): Uint8Array {
  const nsm = requireNative();
  try {
    return nsm.call(Buffer.from(request));
  } catch {
    throw new Error('nsm_unavailable');
  }
}

function requireNative(): { call(request: Buffer): Buffer } {
  return require('../native/nsm.node') as { call(request: Buffer): Buffer };
}
