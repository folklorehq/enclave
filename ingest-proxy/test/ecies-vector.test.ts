import { createDecipheriv, createPrivateKey, createPublicKey, diffieHellman } from 'crypto';
import { describe, expect, it } from 'vitest';
import { deriveAesKey } from '../src/handler.js';

// Frozen known-answer vector for the ingest ECIES scheme (ephemeral X25519 → HKDF-SHA256
// with info `folklore-ingest-v1:` + both pubkeys → AES-256-GCM). Duplicated byte-for-byte in
// packages/crypto/test/ecies-vector.test.ts and enclave/tests/ecies-vector.test.ts — the scheme
// is triplicated by design across the public-mirror boundary (ADL #35), so a one-char drift in
// the info string / HKDF / tag convention in any copy silently breaks production ingest. This
// side only encrypts, so the vector is asserted against the derivation + GCM tag convention.
const VECTOR = {
  recipientPrivHex: '3844d07cc230289eb190ff7730d8247abb9b22f721101cee95d17e79034b114f',
  recipientPubHex: '66b4c01078fad1d9612fc0ff56ec9bd42d22046adcec4f063ce931d9895d7b3d',
  ephemeralPubHex: '0ef6f071c20adfa72939b03d40d8f2db15a00652b994a6143c975b06c98cff17',
  aesKeyHex: 'f86e4dd2c4fa9b33b03f310d45a0df9566721ae99df3a1ae62249b826732cf3d',
  nonceHex: '0102030405060708090a0b0c',
  plaintext: '{"folklore-ingest-known-answer":"v1","n":42}',
  ciphertextHex:
    '5fa2c3279e83c89f49ccfc8439e58832aa5c28eb0709c760c73a0eabc56d6bb7ea37b216c9a378ddf4cf055c78f715c5e7e6ca41d9e929fb27bcbe88',
} as const;

function x25519Public(pubHex: string) {
  return createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(pubHex, 'hex').toString('base64url') },
    format: 'jwk',
  });
}

function x25519Private(privHex: string, pubHex: string) {
  return createPrivateKey({
    key: {
      kty: 'OKP',
      crv: 'X25519',
      d: Buffer.from(privHex, 'hex').toString('base64url'),
      x: Buffer.from(pubHex, 'hex').toString('base64url'),
    },
    format: 'jwk',
  });
}

describe('ingest ECIES known-answer vector', () => {
  it('derives the frozen AES key and honors the GCM tag convention', () => {
    const sharedSecret = diffieHellman({
      privateKey: x25519Private(VECTOR.recipientPrivHex, VECTOR.recipientPubHex),
      publicKey: x25519Public(VECTOR.ephemeralPubHex),
    });
    const aesKey = deriveAesKey(
      sharedSecret,
      Buffer.from(VECTOR.ephemeralPubHex, 'hex'),
      Buffer.from(VECTOR.recipientPubHex, 'hex'),
    );
    expect(aesKey.toString('hex')).toBe(VECTOR.aesKeyHex);

    const ciphertextWithTag = Buffer.from(VECTOR.ciphertextHex, 'hex');
    const decipher = createDecipheriv('aes-256-gcm', aesKey, Buffer.from(VECTOR.nonceHex, 'hex'));
    decipher.setAuthTag(ciphertextWithTag.slice(-16));
    const plaintext = Buffer.concat([
      decipher.update(ciphertextWithTag.slice(0, -16)),
      decipher.final(),
    ]);
    expect(plaintext.toString('utf8')).toBe(VECTOR.plaintext);
  });
});
