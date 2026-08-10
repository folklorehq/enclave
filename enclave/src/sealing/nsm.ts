import { randomBytes } from 'node:crypto';
import { decode } from 'cborg';

const STUB = process.env['NSM_STUB'] === '1';
const REQUEST_MAX_BYTES = 512;
const RESPONSE_MAX_BYTES = 16 * 1024;
const NONCE_BYTES = 32;
const ENTROPY_MAX_BYTES = 256;

const decodeOptions = {
  strict: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowBigInt: false,
} as const;

export interface NsmAttestationRequest {
  publicKey: Uint8Array;
  nonce?: Uint8Array;
  userData?: Uint8Array;
}

export interface NsmIoctlPort {
  call(request: Uint8Array): Uint8Array;
}

export interface NsmAttestationPort {
  attest(request: NsmAttestationRequest): Uint8Array | Promise<Uint8Array>;
}

export interface NsmEntropyPort {
  getEntropy(bytes: number): Uint8Array;
}

export function createNsmEntropyPort(ioctl: NsmIoctlPort): NsmEntropyPort {
  return {
    getEntropy(bytes) {
      validateEntropyRequest(bytes);
      let response: Uint8Array;
      try {
        response = ioctl.call(encodeGetRandomRequest());
      } catch {
        throw new Error('nsm_unavailable');
      }
      const entropy = decodeNsmResponse(response, 'GetRandom', 'random');
      if (entropy.byteLength < bytes) throw new Error('nsm_invalid_response');
      return entropy.subarray(0, bytes);
    },
  };
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

export function getEntropy(bytes: number): Buffer {
  validateEntropyRequest(bytes);
  if (STUB) return randomBytes(bytes);
  return Buffer.from(createNsmEntropyPort(nativeIoctlPort).getEntropy(bytes));
}

export function getAttestationDoc(input: Uint8Array | NsmAttestationRequest): Buffer {
  const request = normalizeAttestationRequest(input);
  encodeAttestationRequest(request);
  if (STUB) {
    return Buffer.concat([Buffer.alloc(48), Buffer.from(request.publicKey)]);
  }
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

function encodeGetRandomRequest(): Uint8Array {
  return Uint8Array.from([0x69, ...Buffer.from('GetRandom')]);
}

function validateEntropyRequest(bytes: number): void {
  if (!Number.isInteger(bytes) || bytes < 1 || bytes > ENTROPY_MAX_BYTES) {
    throw new Error('nsm_invalid_entropy_request');
  }
}

function encodeAttestationRequest(request: NsmAttestationRequest): Uint8Array {
  const publicKey = validateByteString(request.publicKey, false);
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
    ...encodeByteString(publicKey),
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
  return validateByteString(value, false);
}

function validateByteString(value: unknown, allowEmpty: boolean): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    (!allowEmpty && value.byteLength === 0) ||
    value.byteLength > REQUEST_MAX_BYTES
  ) {
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
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require('../native/nsm.node') as { call(request: Buffer): Buffer };
}
