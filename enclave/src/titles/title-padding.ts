import { timingSafeEqual } from 'node:crypto';
import type { SealedTitleRef } from '../crypto/esdk.js';
import type { TenantKeyedHasher } from '../sealing/TenantKeyedHasher.js';

export const SEALED_TITLE_PADDED_BYTES = 1024;
export const SEALED_TITLE_MAC_BYTES = 32;

const LENGTH_PREFIX_BYTES = 2;
const BODY_BYTES = SEALED_TITLE_PADDED_BYTES - SEALED_TITLE_MAC_BYTES;
const MAX_TITLE_BYTES = BODY_BYTES - LENGTH_PREFIX_BYTES;
const MAC_DOMAIN = 'folklore:sealed-title-mac:v1\0';

export type TitleMac = (title: string) => Buffer;

// The MAC key derives from the attested master key, which host credentials cannot reach.
export function sealedTitleMac(hasher: TenantKeyedHasher, binding: SealedTitleRef): TitleMac {
  const { orgId, kind, subjectId, rowId } = binding;
  return (title) =>
    hasher
      .begin(MAC_DOMAIN)
      .update(JSON.stringify([orgId, kind, subjectId, rowId, title]))
      .digest();
}

export function padTitle(title: string, mac: TitleMac): Buffer {
  const bytes = Buffer.from(title, 'utf8');
  if (bytes.length > MAX_TITLE_BYTES) throw new Error('sealed_title_too_long');
  // A lone surrogate does not survive UTF-8, so the MAC would never match on open.
  if (bytes.toString('utf8') !== title) throw new Error('sealed_title_invalid');
  const padded = Buffer.alloc(SEALED_TITLE_PADDED_BYTES);
  padded.writeUInt16BE(bytes.length, 0);
  bytes.copy(padded, LENGTH_PREFIX_BYTES);
  mac(title).copy(padded, BODY_BYTES);
  return padded;
}

export function unpadTitle(padded: Buffer, mac: TitleMac): string {
  if (padded.length !== SEALED_TITLE_PADDED_BYTES) throw new Error('sealed_title_malformed');
  const length = padded.readUInt16BE(0);
  if (length > MAX_TITLE_BYTES) throw new Error('sealed_title_malformed');
  const title = padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + length).toString('utf8');
  const expected = mac(title);
  if (!timingSafeEqual(padded.subarray(BODY_BYTES), expected)) {
    throw new Error('sealed_title_malformed');
  }
  return title;
}
