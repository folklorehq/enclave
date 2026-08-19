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
    return Buffer.concat([
      Buffer.alloc(48),
      request.publicKey === undefined ? Buffer.alloc(0) : Buffer.from(request.publicKey),
    ]);
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
  const publicKey = validateOptionalByteString(request.publicKey);
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
  return validateByteString(value, false);
}

function validateOptionalByteString(value: Uint8Array | undefined): Uint8Array | undefined {
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

// Evidence anchor (PR5): the NSM user-data anchor is a canonical CBOR map with exactly twelve
// integer keys, no unknown keys, and a maximum full request size of 512 bytes. The exact keys are
// version, purpose code, domain code, context digest, org ID, deployment ID, session ID, boot
// epoch, policy generation, keyset high-water epoch, keyset high-water digest, and nonce. Raw NSM
// documents, wire bytes, receipt ids, proof ids, and customer content never leave enclave memory.
export const EVIDENCE_ANCHOR_CBOR_VERSION = 1 as const;
export const EVIDENCE_ANCHOR_PURPOSE_CODE = 1 as const;
export const EVIDENCE_ANCHOR_DOMAIN_CODE = 1 as const;
export const EVIDENCE_ANCHOR_MAX_BYTES = 512;
export const EVIDENCE_ANCHOR_NONCE_BYTES = 32;
const EVIDENCE_ANCHOR_KEY_COUNT = 12;
const EVIDENCE_ANCHOR_LAST_KEY = 12;
const EVIDENCE_ANCHOR_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

export interface EvidenceAnchorCborFields {
  version: number;
  purposeCode: number;
  domainCode: number;
  contextDigest: string;
  orgId: string;
  deploymentId: string;
  sessionId: string;
  bootEpoch: number;
  policyGeneration: number;
  keysetHighWaterEpoch: number;
  keysetHighWaterDigest: string;
  nonce: Uint8Array;
}

export function encodeEvidenceAnchorCbor(fields: EvidenceAnchorCborFields): Uint8Array {
  const values = validateAnchorFields(fields);
  const body: number[] = [];
  const entries: ReadonlyArray<readonly [number, readonly number[]]> = [
    [1, encodeAnchorUint(values.version)],
    [2, encodeAnchorUint(values.purposeCode)],
    [3, encodeAnchorUint(values.domainCode)],
    [4, encodeAnchorText(values.contextDigest)],
    [5, encodeAnchorText(values.orgId)],
    [6, encodeAnchorText(values.deploymentId)],
    [7, encodeAnchorText(values.sessionId)],
    [8, encodeAnchorUint(values.bootEpoch)],
    [9, encodeAnchorUint(values.policyGeneration)],
    [10, encodeAnchorUint(values.keysetHighWaterEpoch)],
    [11, encodeAnchorText(values.keysetHighWaterDigest)],
    [12, encodeAnchorBytes(values.nonce)],
  ];
  for (const [key, value] of entries) {
    body.push(key, ...value);
  }
  if (body.length + 1 > EVIDENCE_ANCHOR_MAX_BYTES) throw new Error('nsm_invalid_request');
  return Uint8Array.from([0xa0 | EVIDENCE_ANCHOR_KEY_COUNT, ...body]);
}

export function decodeEvidenceAnchorCbor(bytes: Uint8Array): EvidenceAnchorCborFields {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength === 0 ||
    bytes.byteLength > EVIDENCE_ANCHOR_MAX_BYTES
  ) {
    throw new Error('nsm_invalid_response');
  }
  let offset = 0;
  const head = readAnchorByte(bytes, offset);
  offset += 1;
  if (head !== (0xa0 | EVIDENCE_ANCHOR_KEY_COUNT)) throw new Error('nsm_invalid_response');
  const fields: Record<number, unknown> = {};
  let previousKey = 0;
  for (let index = 0; index < EVIDENCE_ANCHOR_KEY_COUNT; index += 1) {
    const key = readAnchorByte(bytes, offset);
    offset += 1;
    if (key < 1 || key > EVIDENCE_ANCHOR_LAST_KEY || key <= previousKey) {
      throw new Error('nsm_invalid_response');
    }
    previousKey = key;
    const next = readAnchorValue(bytes, offset, key);
    offset = next.offset;
    fields[key] = next.value;
  }
  if (offset !== bytes.byteLength) throw new Error('nsm_invalid_response');
  return normalizeAnchorFields(fields);
}

function readAnchorValue(
  bytes: Uint8Array,
  offset: number,
  key: number,
): { value: unknown; offset: number } {
  switch (key) {
    case 1:
    case 2:
    case 3:
    case 8:
    case 9:
    case 10:
      return readAnchorUint(bytes, offset);
    case 4:
    case 5:
    case 6:
    case 7:
    case 11:
      return readAnchorText(bytes, offset);
    case 12:
      return readAnchorBytes(bytes, offset);
    default:
      throw new Error('nsm_invalid_response');
  }
}

function validateAnchorFields(fields: EvidenceAnchorCborFields): EvidenceAnchorCborFields {
  if (
    !isAnchorUint(fields.version) ||
    !isAnchorUint(fields.purposeCode) ||
    !isAnchorUint(fields.domainCode)
  ) {
    throw new Error('nsm_invalid_request');
  }
  if (
    !isAnchorUint(fields.bootEpoch) ||
    !isAnchorUint(fields.policyGeneration) ||
    !isAnchorUint(fields.keysetHighWaterEpoch)
  ) {
    throw new Error('nsm_invalid_request');
  }
  if (
    !EVIDENCE_ANCHOR_DIGEST_PATTERN.test(fields.contextDigest) ||
    !EVIDENCE_ANCHOR_DIGEST_PATTERN.test(fields.keysetHighWaterDigest)
  ) {
    throw new Error('nsm_invalid_request');
  }
  if (
    !isAnchorText(fields.orgId) ||
    !isAnchorText(fields.deploymentId) ||
    !isAnchorText(fields.sessionId)
  ) {
    throw new Error('nsm_invalid_request');
  }
  if (
    !(fields.nonce instanceof Uint8Array) ||
    fields.nonce.byteLength !== EVIDENCE_ANCHOR_NONCE_BYTES
  ) {
    throw new Error('nsm_invalid_request');
  }
  return fields;
}

function normalizeAnchorFields(fields: Record<number, unknown>): EvidenceAnchorCborFields {
  const version = fields[1] as number;
  const purposeCode = fields[2] as number;
  const domainCode = fields[3] as number;
  const contextDigest = fields[4] as string;
  const orgId = fields[5] as string;
  const deploymentId = fields[6] as string;
  const sessionId = fields[7] as string;
  const bootEpoch = fields[8] as number;
  const policyGeneration = fields[9] as number;
  const keysetHighWaterEpoch = fields[10] as number;
  const keysetHighWaterDigest = fields[11] as string;
  const nonce = fields[12] as Uint8Array;
  const normalized = {
    version,
    purposeCode,
    domainCode,
    contextDigest,
    orgId,
    deploymentId,
    sessionId,
    bootEpoch,
    policyGeneration,
    keysetHighWaterEpoch,
    keysetHighWaterDigest,
    nonce,
  };
  return validateAnchorFields(normalized);
}

function isAnchorUint(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isAnchorText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= EVIDENCE_ANCHOR_MAX_BYTES;
}

function encodeAnchorUint(value: number): number[] {
  if (!isAnchorUint(value)) throw new Error('nsm_invalid_request');
  if (value < 24) return [value];
  if (value <= 0xff) return [0x18, value];
  if (value <= 0xffff) return [0x19, value >> 8, value & 0xff];
  return [0x1a, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

function encodeAnchorText(value: string): number[] {
  if (!isAnchorText(value)) throw new Error('nsm_invalid_request');
  const bytes = [...Buffer.from(value, 'utf8')];
  if (bytes.length < 24) return [0x60 + bytes.length, ...bytes];
  if (bytes.length <= 0xff) return [0x78, bytes.length, ...bytes];
  throw new Error('nsm_invalid_request');
}

function encodeAnchorBytes(value: Uint8Array): number[] {
  if (!(value instanceof Uint8Array) || value.byteLength !== EVIDENCE_ANCHOR_NONCE_BYTES) {
    throw new Error('nsm_invalid_request');
  }
  return [0x58, EVIDENCE_ANCHOR_NONCE_BYTES, ...value];
}

function readAnchorByte(bytes: Uint8Array, offset: number): number {
  const value = bytes[offset];
  if (value === undefined) throw new Error('nsm_invalid_response');
  return value;
}

function readAnchorUint(bytes: Uint8Array, offset: number): { value: number; offset: number } {
  const initial = readAnchorByte(bytes, offset);
  offset += 1;
  let value: number;
  if (initial < 0x18) {
    value = initial;
  } else if (initial === 0x18) {
    value = readAnchorByte(bytes, offset);
    offset += 1;
    if (value < 24) throw new Error('nsm_invalid_response');
  } else if (initial === 0x19) {
    const high = readAnchorByte(bytes, offset);
    const low = readAnchorByte(bytes, offset + 1);
    offset += 2;
    value = (high << 8) | low;
    if (value <= 0xff) throw new Error('nsm_invalid_response');
  } else if (initial === 0x1a) {
    value =
      (readAnchorByte(bytes, offset) << 24) |
      (readAnchorByte(bytes, offset + 1) << 16) |
      (readAnchorByte(bytes, offset + 2) << 8) |
      readAnchorByte(bytes, offset + 3);
    offset += 4;
    if (value <= 0xffff) throw new Error('nsm_invalid_response');
  } else {
    throw new Error('nsm_invalid_response');
  }
  return { value, offset };
}

function readAnchorText(bytes: Uint8Array, offset: number): { value: string; offset: number } {
  const initial = readAnchorByte(bytes, offset);
  offset += 1;
  let length: number;
  if (initial >= 0x60 && initial <= 0x77) {
    length = initial - 0x60;
  } else if (initial === 0x78) {
    length = readAnchorByte(bytes, offset);
    offset += 1;
    if (length < 24) throw new Error('nsm_invalid_response');
  } else {
    throw new Error('nsm_invalid_response');
  }
  const raw = bytes.subarray(offset, offset + length);
  if (raw.byteLength !== length) throw new Error('nsm_invalid_response');
  offset += length;
  const value = Buffer.from(raw).toString('utf8');
  if (Buffer.byteLength(value, 'utf8') !== length) throw new Error('nsm_invalid_response');
  return { value, offset };
}

function readAnchorBytes(bytes: Uint8Array, offset: number): { value: Uint8Array; offset: number } {
  const initial = readAnchorByte(bytes, offset);
  offset += 1;
  let length: number;
  if (initial === 0x58) {
    length = readAnchorByte(bytes, offset);
    offset += 1;
  } else if (initial >= 0x40 && initial <= 0x57) {
    length = initial - 0x40;
  } else {
    throw new Error('nsm_invalid_response');
  }
  if (length !== EVIDENCE_ANCHOR_NONCE_BYTES) throw new Error('nsm_invalid_response');
  const value = bytes.subarray(offset, offset + length);
  if (value.byteLength !== length) throw new Error('nsm_invalid_response');
  return { value: Uint8Array.from(value), offset: offset + length };
}
