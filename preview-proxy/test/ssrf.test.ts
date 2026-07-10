import { describe, expect, it } from 'vitest';
import { assertPublicIp, isPublicIp, parseIPv6, SsrfBlockedError } from '../src/ssrf.js';

describe('isPublicIp — IPv4', () => {
  const blocked = [
    '0.0.0.0',
    '10.0.0.1',
    '10.255.255.255',
    '100.64.0.1',
    '127.0.0.1',
    '127.1.2.3',
    '169.254.169.254',
    '169.254.0.1',
    '172.16.0.1',
    '172.31.255.255',
    '192.0.0.1',
    '192.0.2.5',
    '192.88.99.1',
    '192.168.1.1',
    '198.18.0.1',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '240.0.0.1',
    '255.255.255.255',
  ];
  for (const ip of blocked) {
    it(`blocks ${ip}`, () => expect(isPublicIp(ip)).toBe(false));
  }

  const allowed = [
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '172.15.255.255',
    '172.32.0.1',
    '11.0.0.1',
  ];
  for (const ip of allowed) {
    it(`allows ${ip}`, () => expect(isPublicIp(ip)).toBe(true));
  }
});

describe('isPublicIp — IPv6', () => {
  const blocked = [
    '::1',
    '::',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'ff02::1',
    '2001:db8::1',
    '2001:20::1',
    '2001:2f:ffff::1',
    '3ffe::1',
    'fec0::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
    '::ffff:169.254.169.254',
    '64:ff9b::7f00:1',
    '2002:c0a8:0101::1',
  ];
  for (const ip of blocked) {
    it(`blocks ${ip}`, () => expect(isPublicIp(ip)).toBe(false));
  }

  const allowed = ['2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8'];
  for (const ip of allowed) {
    it(`allows ${ip}`, () => expect(isPublicIp(ip)).toBe(true));
  }
});

describe('parseIPv6', () => {
  it('expands :: shorthand to 16 bytes', () => {
    expect(parseIPv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  });
  it('parses ipv4-mapped tail', () => {
    expect(parseIPv6('::ffff:192.168.0.1')?.slice(12)).toEqual([192, 168, 0, 1]);
  });
  it('rejects a double ::', () => expect(parseIPv6('1::2::3')).toBeNull());
  it('rejects garbage', () => expect(parseIPv6('nope')).toBeNull());
});

describe('assertPublicIp', () => {
  it('throws SsrfBlockedError for a private address', () => {
    expect(() => assertPublicIp('10.0.0.1')).toThrow(SsrfBlockedError);
  });
  it('does not throw for a public address', () => {
    expect(() => assertPublicIp('8.8.8.8')).not.toThrow();
  });
});
