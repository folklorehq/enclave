import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import * as asn1js from 'asn1js';

const ECDSA_WITH_SHA256_OID = '1.2.840.10045.4.3.2';
const COMMON_NAME_OID = '2.5.4.3';
const P256_CURVE_NAME = 'prime256v1';
const P256_UNCOMPRESSED_SPKI_LENGTH = 91;
const P256_UNCOMPRESSED_POINT_LENGTH = 65;
const UNCOMPRESSED_POINT_PREFIX = 0x04;
const SIGNATURE_DIGEST = 'sha256';
// Control characters and lone surrogates: the latter cannot be encoded as UTF-8 at all.
const COMMON_NAME_FORBIDDEN = /[\p{Cc}\p{Cs}]/u;
const SERIAL_LENGTH = 16;
const SERIAL_FIRST_BYTE_MIN = 0x01;
const SERIAL_FIRST_BYTE_MAX = 0x7f;
const COMMON_NAME_MAX_LENGTH = 64;
const UTC_TIME_FIRST_YEAR = 1950;
const UTC_TIME_LAST_YEAR = 2049;
// RFC 5280 4.1.2.5: a certificate with no well-defined expiry uses this GeneralizedTime.
const NO_WELL_DEFINED_EXPIRY = new Date(Date.UTC(9999, 11, 31, 23, 59, 59));

export type SelfSignedCertificateErrorCode =
  | 'certificate_serial_invalid'
  | 'certificate_common_name_invalid'
  | 'certificate_not_before_invalid'
  | 'certificate_public_key_invalid'
  | 'certificate_signature_invalid';

export class SelfSignedCertificateError extends Error {
  readonly code: SelfSignedCertificateErrorCode;

  constructor(code: SelfSignedCertificateErrorCode) {
    super(code);
    this.name = 'SelfSignedCertificateError';
    this.code = code;
  }
}

export interface SelfSignedEcdsaCertificateInput {
  readonly commonName: string;
  readonly serial: Uint8Array;
  readonly notBefore: Date;
  readonly subjectPublicKeyInfoDer: Uint8Array;
}

/** Encodes the TBSCertificate of an X.509 v1, ecdsa-with-SHA256, self-issued certificate. */
export function buildSelfSignedEcdsaCertificateTbs(
  input: SelfSignedEcdsaCertificateInput,
): Uint8Array {
  const subjectKey = p256UncompressedPublicKey(input.subjectPublicKeyInfoDer);
  return new Uint8Array(tbsCertificate(input, subjectKey).toBER());
}

/** Builds the DER certificate; the caller signs the TBS bytes, and the signature must verify. */
export function buildSelfSignedEcdsaCertificate(
  input: SelfSignedEcdsaCertificateInput & {
    readonly signTbs: (tbsDer: Uint8Array) => Uint8Array;
  },
): Uint8Array {
  const subjectKey = p256UncompressedPublicKey(input.subjectPublicKeyInfoDer);
  const tbs = tbsCertificate(input, subjectKey);
  const tbsDer = new Uint8Array(tbs.toBER());
  const signature = input.signTbs(tbsDer);
  if (!signatureVerifies(tbsDer, subjectKey, signature)) {
    throw new SelfSignedCertificateError('certificate_signature_invalid');
  }
  const certificate = new asn1js.Sequence({
    value: [tbs, ecdsaWithSha256(), new asn1js.BitString({ valueHex: signature })],
  });
  return new Uint8Array(certificate.toBER());
}

function tbsCertificate(
  input: SelfSignedEcdsaCertificateInput,
  subjectKey: KeyObject,
): asn1js.Sequence {
  const name = commonNameOnly(input.commonName);
  return new asn1js.Sequence({
    value: [
      positiveSerial(input.serial),
      ecdsaWithSha256(),
      name,
      validity(input.notBefore),
      name,
      asn1js.fromBER(new Uint8Array(subjectKey.export({ type: 'spki', format: 'der' }))).result,
    ],
  });
}

function positiveSerial(serial: Uint8Array): asn1js.Integer {
  const first = serial[0];
  if (
    serial.length !== SERIAL_LENGTH ||
    first === undefined ||
    first < SERIAL_FIRST_BYTE_MIN ||
    first > SERIAL_FIRST_BYTE_MAX
  ) {
    throw new SelfSignedCertificateError('certificate_serial_invalid');
  }
  return new asn1js.Integer({ valueHex: Uint8Array.from(serial) });
}

function ecdsaWithSha256(): asn1js.Sequence {
  return new asn1js.Sequence({
    value: [new asn1js.ObjectIdentifier({ value: ECDSA_WITH_SHA256_OID })],
  });
}

function commonNameOnly(commonName: string): asn1js.Sequence {
  if (
    commonName.length === 0 ||
    commonName.length > COMMON_NAME_MAX_LENGTH ||
    COMMON_NAME_FORBIDDEN.test(commonName)
  ) {
    throw new SelfSignedCertificateError('certificate_common_name_invalid');
  }
  const attribute = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: COMMON_NAME_OID }),
      new asn1js.Utf8String({ value: commonName }),
    ],
  });
  return new asn1js.Sequence({ value: [new asn1js.Set({ value: [attribute] })] });
}

function validity(notBefore: Date): asn1js.Sequence {
  const year = notBefore.getUTCFullYear();
  if (
    Number.isNaN(notBefore.getTime()) ||
    year < UTC_TIME_FIRST_YEAR ||
    year > UTC_TIME_LAST_YEAR
  ) {
    throw new SelfSignedCertificateError('certificate_not_before_invalid');
  }
  return new asn1js.Sequence({
    value: [
      new asn1js.UTCTime({ valueDate: notBefore }),
      new asn1js.GeneralizedTime({ valueDate: NO_WELL_DEFINED_EXPIRY }),
    ],
  });
}

function p256UncompressedPublicKey(spkiDer: Uint8Array): KeyObject {
  const key = publicKeyOrUndefined(spkiDer);
  if (key?.asymmetricKeyDetails?.namedCurve !== P256_CURVE_NAME) {
    throw new SelfSignedCertificateError('certificate_public_key_invalid');
  }
  const canonical = key.export({ type: 'spki', format: 'der' });
  const pointPrefix = canonical[canonical.length - P256_UNCOMPRESSED_POINT_LENGTH];
  if (
    !canonical.equals(Buffer.from(spkiDer)) ||
    canonical.length !== P256_UNCOMPRESSED_SPKI_LENGTH ||
    pointPrefix !== UNCOMPRESSED_POINT_PREFIX
  ) {
    throw new SelfSignedCertificateError('certificate_public_key_invalid');
  }
  return key;
}

function signatureVerifies(
  tbsDer: Uint8Array,
  subjectKey: KeyObject,
  signature: Uint8Array,
): boolean {
  try {
    return verify(SIGNATURE_DIGEST, tbsDer, subjectKey, signature);
  } catch {
    return false;
  }
}

function publicKeyOrUndefined(spkiDer: Uint8Array): KeyObject | undefined {
  try {
    return createPublicKey({ key: Buffer.from(spkiDer), format: 'der', type: 'spki' });
  } catch {
    return undefined;
  }
}
