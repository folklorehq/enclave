import { decode } from 'cborg';

import { NitroAttestationError } from './failures.js';

const AWS_NITRO_FIELDS = new Set([
  'module_id',
  'digest',
  'timestamp',
  'pcrs',
  'certificate',
  'cabundle',
  'public_key',
  'user_data',
  'nonce',
]);
const MODULE_ID_MAX_LENGTH = 128;
const SHA384_BYTES = 48;
const REQUIRED_PCRS = [0, 3, 4] as const;
const PCR_INDEX_MAX = 31;
const PCR_MAP_MAX_ENTRIES = 32;
const CERTIFICATE_MAX_BYTES = 1_024;
const CA_BUNDLE_MAX_CERTIFICATES = 8;
const ED25519_PUBLIC_KEY_BYTES = 32;
const USER_DATA_MAX_BYTES = 512;

export interface NitroDocumentPayload {
  moduleId: string;
  digest: 'SHA384';
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  publicKey: Uint8Array;
  userData: Uint8Array;
  nonce: Uint8Array;
}

export interface NitroDocumentTrustPathPayload {
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  timestamp: number;
}

const decodeOptions = {
  strict: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowBigInt: false,
  useMaps: true,
  rejectDuplicateMapKeys: true,
} as const;

function decodePayload(payload: Uint8Array): Map<string, unknown> {
  try {
    return decode(payload, decodeOptions) as Map<string, unknown>;
  } catch {
    throw new NitroAttestationError('malformed_document');
  }
}

function readCabundle(fields: Map<string, unknown>): Uint8Array[] {
  const cabundle = fields.get('cabundle');
  if (
    !Array.isArray(cabundle) ||
    cabundle.length === 0 ||
    cabundle.length > CA_BUNDLE_MAX_CERTIFICATES ||
    cabundle.some(
      (item) =>
        !(item instanceof Uint8Array) ||
        item.byteLength === 0 ||
        item.byteLength > CERTIFICATE_MAX_BYTES,
    )
  ) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  return cabundle;
}

function readCertificate(fields: Map<string, unknown>): Uint8Array {
  const certificate = fields.get('certificate');
  if (
    !(certificate instanceof Uint8Array) ||
    certificate.byteLength === 0 ||
    certificate.byteLength > CERTIFICATE_MAX_BYTES
  ) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  return certificate;
}

function readTimestamp(fields: Map<string, unknown>): number {
  const timestamp = fields.get('timestamp');
  if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  return timestamp;
}

function validateDigest(fields: Map<string, unknown>): void {
  if (fields.get('digest') !== 'SHA384') {
    throw new NitroAttestationError('invalid_document_fields');
  }
}

function validateAwsNitroFieldSet(fields: Map<string, unknown>): void {
  if (
    fields.size !== AWS_NITRO_FIELDS.size ||
    [...fields.keys()].some((key) => typeof key !== 'string' || !AWS_NITRO_FIELDS.has(key))
  ) {
    throw new NitroAttestationError('invalid_document_fields');
  }
}

export function parseNitroDocumentTrustPathPayload(
  payload: Uint8Array,
): NitroDocumentTrustPathPayload {
  const fields = decodePayload(payload);
  if (!(fields instanceof Map)) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  validateAwsNitroFieldSet(fields);
  validateDigest(fields);
  return {
    certificate: readCertificate(fields),
    cabundle: readCabundle(fields),
    timestamp: readTimestamp(fields),
  };
}

export function parseNitroDocumentPayload(payload: Uint8Array): NitroDocumentPayload {
  const fields = decodePayload(payload);
  if (!(fields instanceof Map)) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  validateAwsNitroFieldSet(fields);
  const nonce = fields.get('nonce');
  if (!(nonce instanceof Uint8Array) || nonce.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  const publicKey = fields.get('public_key');
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  const userData = fields.get('user_data');
  if (
    !(userData instanceof Uint8Array) ||
    userData.byteLength === 0 ||
    userData.byteLength > USER_DATA_MAX_BYTES
  ) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  const cabundle = readCabundle(fields);
  const certificate = readCertificate(fields);
  validateDigest(fields);
  const moduleId = fields.get('module_id');
  if (
    typeof moduleId !== 'string' ||
    moduleId.length === 0 ||
    moduleId.length > MODULE_ID_MAX_LENGTH
  ) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  const timestamp = readTimestamp(fields);
  const pcrs = fields.get('pcrs');
  if (
    !(pcrs instanceof Map) ||
    pcrs.size > PCR_MAP_MAX_ENTRIES ||
    REQUIRED_PCRS.some((index) => !pcrs.has(index)) ||
    [...pcrs.keys()].some(
      (index) =>
        typeof index !== 'number' ||
        !Number.isSafeInteger(index) ||
        index < 0 ||
        index > PCR_INDEX_MAX,
    ) ||
    [...pcrs.values()].some(
      (value) => !(value instanceof Uint8Array) || value.byteLength !== SHA384_BYTES,
    )
  ) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  const pcr0 = pcrs.get(0);
  if (!(pcr0 instanceof Uint8Array) || !pcr0.some((byte) => byte !== 0)) {
    throw new NitroAttestationError('invalid_document_fields');
  }
  return {
    moduleId,
    digest: fields.get('digest') as 'SHA384',
    timestamp,
    pcrs: pcrs as Map<number, Uint8Array>,
    certificate,
    cabundle,
    publicKey,
    userData,
    nonce,
  };
}
