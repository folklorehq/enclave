import { isIP } from 'node:net';

// SSRF egress guard (ADL #54). The only address class we allow the proxy to connect to
// is public unicast; every private / loopback / link-local / CGNAT / metadata / multicast
// / reserved range — v4, v6, and v4-embedded-in-v6 — is refused before a socket opens.

export class SsrfBlockedError extends Error {
  constructor(reason: string) {
    super(`SSRF blocked: ${reason}`);
    this.name = 'SsrfBlockedError';
  }
}

interface V4Range {
  base: number;
  prefix: number;
}

const V4_BLOCKED: V4Range[] = [
  v4Range('0.0.0.0', 8),
  v4Range('10.0.0.0', 8),
  v4Range('100.64.0.0', 10),
  v4Range('127.0.0.0', 8),
  v4Range('169.254.0.0', 16),
  v4Range('172.16.0.0', 12),
  v4Range('192.0.0.0', 24),
  v4Range('192.0.2.0', 24),
  v4Range('192.88.99.0', 24),
  v4Range('192.168.0.0', 16),
  v4Range('198.18.0.0', 15),
  v4Range('198.51.100.0', 24),
  v4Range('203.0.113.0', 24),
  v4Range('224.0.0.0', 4),
  v4Range('240.0.0.0', 4),
];

interface V6Range {
  bytes: number[];
  prefix: number;
}

const V6_BLOCKED: V6Range[] = [
  v6Range('::1', 128),
  v6Range('::', 128),
  v6Range('fc00::', 7),
  v6Range('fe80::', 10),
  v6Range('ff00::', 8),
  v6Range('2001:db8::', 32),
  v6Range('2001::', 32),
  v6Range('2001:20::', 28),
  v6Range('2002::', 16),
  v6Range('3ffe::', 16),
  v6Range('64:ff9b::', 96),
  v6Range('fec0::', 10),
];

function v4Range(cidr: string, prefix: number): V4Range {
  const base = parseIPv4(cidr);
  if (base === null) throw new Error(`invalid v4 range: ${cidr}`);
  return { base: applyV4Mask(base, prefix), prefix };
}

function v6Range(addr: string, prefix: number): V6Range {
  const bytes = parseIPv6(addr);
  if (bytes === null) throw new Error(`invalid v6 range: ${addr}`);
  return { bytes, prefix };
}

export function parseIPv4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

function applyV4Mask(value: number, prefix: number): number {
  if (prefix === 0) return 0;
  const mask = prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) >>> 0;
}

export function parseIPv6(ip: string): number[] | null {
  let head = ip;
  let embeddedV4: number[] | null = null;
  const lastColon = head.lastIndexOf(':');
  if (head.slice(lastColon + 1).includes('.')) {
    const dotted = head.slice(lastColon + 1);
    const v4 = parseIPv4(dotted);
    if (v4 === null) return null;
    embeddedV4 = [(v4 >>> 24) & 0xff, (v4 >>> 16) & 0xff, (v4 >>> 8) & 0xff, v4 & 0xff];
    head = head.slice(0, lastColon + 1) + '0:0';
  }

  const halves = head.split('::');
  if (halves.length > 2) return null;

  const groupsToBytes = (groups: string[]): number[] | null => {
    const out: number[] = [];
    for (const group of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      const value = parseInt(group, 16);
      out.push((value >>> 8) & 0xff, value & 0xff);
    }
    return out;
  };

  const leftGroups = halves[0] ? halves[0].split(':') : [];
  const rightGroups = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  const leftBytes = groupsToBytes(leftGroups);
  const rightBytes = groupsToBytes(rightGroups);
  if (leftBytes === null || rightBytes === null) return null;

  let assembled: number[];
  if (halves.length === 2) {
    const gap = 16 - leftBytes.length - rightBytes.length;
    if (gap < 0) return null;
    assembled = [...leftBytes, ...new Array<number>(gap).fill(0), ...rightBytes];
  } else {
    assembled = leftBytes;
  }
  if (embeddedV4) assembled = [...assembled.slice(0, 12), ...embeddedV4];
  return assembled.length === 16 ? assembled : null;
}

function bytesInPrefix(addr: number[], range: V6Range): boolean {
  const fullBytes = range.prefix >> 3;
  const remainingBits = range.prefix & 7;
  for (let i = 0; i < fullBytes; i++) {
    if (addr[i] !== range.bytes[i]) return false;
  }
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (addr[fullBytes]! & mask) === (range.bytes[fullBytes]! & mask);
}

function extractEmbeddedV4(addr: number[]): number | null {
  const first10Zero = addr.slice(0, 10).every((b) => b === 0);
  if (!first10Zero) return null;
  const isMapped = addr[10] === 0xff && addr[11] === 0xff;
  const isCompatible = addr[10] === 0 && addr[11] === 0;
  if (!isMapped && !isCompatible) return null;
  return ((addr[12]! << 24) | (addr[13]! << 16) | (addr[14]! << 8) | addr[15]!) >>> 0;
}

function isPublicV4(value: number): boolean {
  return !V4_BLOCKED.some((range) => applyV4Mask(value, range.prefix) === range.base);
}

function isPublicV6(bytes: number[]): boolean {
  const embedded = extractEmbeddedV4(bytes);
  if (embedded !== null) return isPublicV4(embedded);
  return !V6_BLOCKED.some((range) => bytesInPrefix(bytes, range));
}

export function isPublicIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) {
    const value = parseIPv4(ip);
    return value !== null && isPublicV4(value);
  }
  if (version === 6) {
    const bytes = parseIPv6(ip);
    return bytes !== null && isPublicV6(bytes);
  }
  return false;
}

export function assertPublicIp(ip: string): void {
  if (!isPublicIp(ip)) throw new SsrfBlockedError(`non-public address ${ip}`);
}
