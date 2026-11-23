import { timingSafeEqual } from 'node:crypto';
import type { SealedTitleRef } from '../crypto/esdk.js';
import type { TenantKeyedHasher } from '../sealing/TenantKeyedHasher.js';

export const SEALED_TITLE_PADDED_BYTES = 1024;
export const SEALED_TITLE_MAC_BYTES = 32;

const LENGTH_PREFIX_BYTES = 2;
const BODY_BYTES = SEALED_TITLE_PADDED_BYTES - SEALED_TITLE_MAC_BYTES;
const MAX_TITLE_BYTES = BODY_BYTES - LENGTH_PREFIX_BYTES;
const MAC_DOMAIN = 'folklore:sealed-title-mac:v1\0';
// The stamped form sets the length prefix's top bit, which no plain title length reaches, then carries the
// sealing time and the fallback flag before the title, all under the MAC.
const STAMPED_FLAG = 0x8000;
const STAMP_BYTES = 8 + 1;
const STAMPED_TITLE_OFFSET = LENGTH_PREFIX_BYTES + STAMP_BYTES;
const MAX_STAMPED_TITLE_BYTES = BODY_BYTES - STAMPED_TITLE_OFFSET;
const STAMPED_MAC_DOMAIN = 'folklore:sealed-title-mac:v2\0';

export type TitleMac = (title: string) => Buffer;

// A fallback never displaces a real title; a withdrawn title is one the enclave puts over a real title whose facts became ineligible.
export const TITLE_STANDINGS = ['real', 'fallback', 'withdrawn'] as const;
export type TitleStanding = (typeof TITLE_STANDINGS)[number];

/** When the enclave sealed a title and how it ranks; a plain title is a real one sealed at 0. */
export interface TitleStamp {
  sealedAtMs: number;
  standing: TitleStanding;
}

export interface OpenedTitle {
  title: string;
  stamp: TitleStamp;
}

export type StampedTitleMac = (title: string, stamp: TitleStamp) => Buffer;

export const UNSTAMPED: TitleStamp = Object.freeze({ sealedAtMs: 0, standing: 'real' });

// The MAC key derives from the attested master key, which host credentials cannot reach.
export function sealedTitleMac(hasher: TenantKeyedHasher, binding: SealedTitleRef): TitleMac {
  const { orgId, kind, subjectId, rowId } = binding;
  return (title) =>
    hasher
      .begin(MAC_DOMAIN)
      .update(JSON.stringify([orgId, kind, subjectId, rowId, title]))
      .digest();
}

export function stampedTitleMac(
  hasher: TenantKeyedHasher,
  binding: SealedTitleRef,
): StampedTitleMac {
  const { orgId, kind, subjectId, rowId } = binding;
  return (title, stamp) =>
    hasher
      .begin(STAMPED_MAC_DOMAIN)
      .update(
        JSON.stringify([orgId, kind, subjectId, rowId, stamp.sealedAtMs, stamp.standing, title]),
      )
      .digest();
}

export function padTitle(title: string, mac: TitleMac): Buffer {
  const bytes = titleBytes(title, MAX_TITLE_BYTES);
  const padded = Buffer.alloc(SEALED_TITLE_PADDED_BYTES);
  padded.writeUInt16BE(bytes.length, 0);
  bytes.copy(padded, LENGTH_PREFIX_BYTES);
  mac(title).copy(padded, BODY_BYTES);
  return padded;
}

export function padStampedTitle(title: string, stamp: TitleStamp, mac: StampedTitleMac): Buffer {
  if (
    !Number.isSafeInteger(stamp.sealedAtMs) ||
    stamp.sealedAtMs < 0 ||
    !TITLE_STANDINGS.includes(stamp.standing)
  ) {
    throw new Error('sealed_title_invalid');
  }
  const bytes = titleBytes(title, MAX_STAMPED_TITLE_BYTES);
  const padded = Buffer.alloc(SEALED_TITLE_PADDED_BYTES);
  padded.writeUInt16BE(STAMPED_FLAG | bytes.length, 0);
  padded.writeBigUInt64BE(BigInt(stamp.sealedAtMs), LENGTH_PREFIX_BYTES);
  padded.writeUInt8(TITLE_STANDINGS.indexOf(stamp.standing), LENGTH_PREFIX_BYTES + 8);
  bytes.copy(padded, STAMPED_TITLE_OFFSET);
  mac(title, stamp).copy(padded, BODY_BYTES);
  return padded;
}

export function unpadTitle(padded: Buffer, mac: TitleMac): string {
  if (padded.length !== SEALED_TITLE_PADDED_BYTES) throw new Error('sealed_title_malformed');
  const length = padded.readUInt16BE(0);
  if (length > MAX_TITLE_BYTES) throw new Error('sealed_title_malformed');
  const title = padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + length).toString('utf8');
  verifyMac(padded, mac(title));
  return title;
}

/** Opens either form: a plain title reads as a real one sealed at 0, so any stamped title outranks it. */
export function openTitle(padded: Buffer, plain: TitleMac, stamped: StampedTitleMac): OpenedTitle {
  if (padded.length !== SEALED_TITLE_PADDED_BYTES) throw new Error('sealed_title_malformed');
  const prefix = padded.readUInt16BE(0);
  if ((prefix & STAMPED_FLAG) === 0) return { title: unpadTitle(padded, plain), stamp: UNSTAMPED };
  const length = prefix & ~STAMPED_FLAG;
  if (length > MAX_STAMPED_TITLE_BYTES) throw new Error('sealed_title_malformed');
  const sealedAt = padded.readBigUInt64BE(LENGTH_PREFIX_BYTES);
  const standing = TITLE_STANDINGS[padded.readUInt8(LENGTH_PREFIX_BYTES + 8)];
  if (sealedAt > BigInt(Number.MAX_SAFE_INTEGER) || standing === undefined) {
    throw new Error('sealed_title_malformed');
  }
  const stamp = { sealedAtMs: Number(sealedAt), standing };
  const title = padded
    .subarray(STAMPED_TITLE_OFFSET, STAMPED_TITLE_OFFSET + length)
    .toString('utf8');
  verifyMac(padded, stamped(title, stamp));
  return { title, stamp };
}

function titleBytes(title: string, max: number): Buffer {
  const bytes = Buffer.from(title, 'utf8');
  if (bytes.length > max) throw new Error('sealed_title_too_long');
  // A lone surrogate does not survive UTF-8, so the MAC would never match on open.
  if (bytes.toString('utf8') !== title) throw new Error('sealed_title_invalid');
  return bytes;
}

function verifyMac(padded: Buffer, expected: Buffer): void {
  if (!timingSafeEqual(padded.subarray(BODY_BYTES), expected)) {
    throw new Error('sealed_title_malformed');
  }
}
