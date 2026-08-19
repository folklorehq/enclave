import { createHash, timingSafeEqual } from 'node:crypto';
import { decode } from 'cborg';
import { verifyAwsNitroAttestationDocument } from '@folklore/nitro-attestation';
import type { NsmAttestationPort } from '../sealing/nsm.js';
import type { NsmAttestationDocumentV1, NsmTrustedTimeSourcePort } from '@folklore/inference';

export interface NsmTrustedTimeSourceOptions {
  readonly nsm: NsmAttestationPort;
  readonly publicKey?: Uint8Array;
}

interface TaggedCoseDocument {
  readonly tag: 18;
  readonly value: readonly unknown[];
}

interface ParsedNsmDocument {
  readonly timestampMs: number;
  readonly nonce: Uint8Array;
  readonly userData: Uint8Array;
  readonly pcr0: Uint8Array;
  readonly publicKey: Uint8Array | null;
}

const NONCE_BYTES = 32;
const PUBLIC_KEY_BYTES = 32;
const PCR0_BYTES = 48;
const USER_DATA_MAX_BYTES = 512;
const DOCUMENT_MAX_BYTES = 16 * 1024;
const decodeOptions = {
  strict: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowBigInt: false,
  tags: {
    18: (decodeTagged: () => unknown): unknown => ({ tag: 18, value: decodeTagged() }),
  },
} as const;

export class NsmTrustedTimeSource implements NsmTrustedTimeSourcePort {
  readonly #publicKey: Uint8Array | undefined;

  constructor(private readonly options: NsmTrustedTimeSourceOptions) {
    if (
      options.publicKey !== undefined &&
      (!(options.publicKey instanceof Uint8Array) ||
        options.publicKey.byteLength !== PUBLIC_KEY_BYTES)
    ) {
      throw new Error('nsm_attestation_invalid');
    }
    this.#publicKey =
      options.publicKey === undefined ? undefined : Uint8Array.from(options.publicKey);
  }

  async attest(input: {
    nonce: Uint8Array;
    userData: Uint8Array;
  }): Promise<NsmAttestationDocumentV1> {
    this.validateRequest(input);
    let rawDocument: Uint8Array;
    try {
      rawDocument = await this.options.nsm.attest({
        publicKey: this.#publicKey === undefined ? undefined : Uint8Array.from(this.#publicKey),
        nonce: Uint8Array.from(input.nonce),
        userData: Uint8Array.from(input.userData),
      });
    } catch {
      throw new Error('nsm_attestation_invalid');
    }
    if (!(rawDocument instanceof Uint8Array) || rawDocument.byteLength > DOCUMENT_MAX_BYTES) {
      throw new Error('nsm_attestation_invalid');
    }
    const verified = verifyAwsNitroAttestationDocument(rawDocument);
    if (!verified.ok) throw new Error('nsm_attestation_invalid');
    try {
      const document = this.readDocument(rawDocument);
      if (
        !this.equalBytes(document.nonce, input.nonce) ||
        !this.equalBytes(document.userData, input.userData) ||
        !this.equalOptionalBytes(document.publicKey, this.#publicKey)
      ) {
        throw new Error('invalid');
      }
      return {
        timestampMs: document.timestampMs,
        nonce: Uint8Array.from(document.nonce),
        userData: Uint8Array.from(document.userData),
        pcr0: Buffer.from(document.pcr0).toString('hex'),
        documentDigest: createHash('sha256').update(rawDocument).digest('hex'),
        publicKey: document.publicKey === null ? null : Uint8Array.from(document.publicKey),
        chainVerified: true,
        rootVerified: true,
        signatureVerified: true,
      };
    } catch {
      throw new Error('nsm_attestation_invalid');
    }
  }

  private validateRequest(input: { nonce: Uint8Array; userData: Uint8Array }): void {
    if (
      input === null ||
      typeof input !== 'object' ||
      !(input.nonce instanceof Uint8Array) ||
      input.nonce.byteLength !== NONCE_BYTES ||
      !(input.userData instanceof Uint8Array) ||
      input.userData.byteLength === 0 ||
      input.userData.byteLength > USER_DATA_MAX_BYTES
    ) {
      throw new Error('nsm_attestation_invalid');
    }
  }

  private readDocument(document: Uint8Array): ParsedNsmDocument {
    const cose = this.decodeCose(document);
    const payload = cose.value[2];
    if (!(payload instanceof Uint8Array)) throw new Error('invalid');
    const fields = this.decodeMap(payload);
    const expectedFields = new Set([
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
    if (
      fields.size !== expectedFields.size ||
      [...fields.keys()].some((key) => typeof key !== 'string' || !expectedFields.has(key))
    ) {
      throw new Error('invalid');
    }
    if (fields.get('digest') !== 'SHA384') throw new Error('invalid');
    const timestampMs = fields.get('timestamp');
    const nonce = fields.get('nonce');
    const userData = fields.get('user_data');
    const pcrs = fields.get('pcrs');
    const publicKey = fields.get('public_key');
    if (
      typeof timestampMs !== 'number' ||
      !Number.isSafeInteger(timestampMs) ||
      timestampMs <= 0 ||
      !(nonce instanceof Uint8Array) ||
      nonce.byteLength !== NONCE_BYTES ||
      !(userData instanceof Uint8Array) ||
      userData.byteLength === 0 ||
      userData.byteLength > USER_DATA_MAX_BYTES ||
      !(pcrs instanceof Map) ||
      (publicKey !== null &&
        (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== PUBLIC_KEY_BYTES))
    ) {
      throw new Error('invalid');
    }
    const pcr0 = pcrs.get(0);
    if (!(pcr0 instanceof Uint8Array) || pcr0.byteLength !== PCR0_BYTES || !pcr0.some(Boolean)) {
      throw new Error('invalid');
    }
    return {
      timestampMs,
      nonce,
      userData,
      pcr0,
      publicKey,
    };
  }

  private decodeCose(document: Uint8Array): TaggedCoseDocument {
    const decoded = decode(document, decodeOptions);
    if (
      !this.isTaggedCoseDocument(decoded) ||
      decoded.value.length !== 4 ||
      !(decoded.value[0] instanceof Uint8Array) ||
      !(decoded.value[1] instanceof Map) ||
      decoded.value[1].size !== 0 ||
      !(decoded.value[2] instanceof Uint8Array) ||
      !(decoded.value[3] instanceof Uint8Array)
    ) {
      throw new Error('invalid');
    }
    return decoded;
  }

  private decodeMap(value: Uint8Array): Map<unknown, unknown> {
    const decoded = decode(value, decodeOptions);
    if (!(decoded instanceof Map)) throw new Error('invalid');
    return decoded;
  }

  private isTaggedCoseDocument(value: unknown): value is TaggedCoseDocument {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const tagged = value as { tag?: unknown; value?: unknown };
    return tagged.tag === 18 && Array.isArray(tagged.value);
  }

  private equalOptionalBytes(left: Uint8Array | null, right: Uint8Array | undefined): boolean {
    if (left === null || right === undefined) return left === null && right === undefined;
    return this.equalBytes(left, right);
  }

  private equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    return left.byteLength === right.byteLength && timingSafeEqual(left, right);
  }
}
