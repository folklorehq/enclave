import { createHash } from 'node:crypto';
import { canonicalCbor } from './canonical-cbor.js';

// The one shared domain-separated recipe: UTF8(domain) || 0x00 || canonicalCBOR(orderedArray).
export function domainSeparatedBytes(domain: string, array: unknown[]): Uint8Array {
  const domainBytes = Buffer.from(domain, 'utf8');
  const payload = canonicalCbor(array);
  const joined = new Uint8Array(domainBytes.byteLength + 1 + payload.byteLength);
  joined.set(domainBytes, 0);
  joined[domainBytes.byteLength] = 0x00;
  joined.set(payload, domainBytes.byteLength + 1);
  return joined;
}

// The same recipe over SHA-256(bytes), for inputs that can outgrow a KMS Sign message.
export function domainSeparatedDigest(domain: string, bytes: Uint8Array): Uint8Array {
  const domainBytes = Buffer.from(domain, 'utf8');
  const digest = createHash('sha256').update(bytes).digest();
  const input = new Uint8Array(domainBytes.byteLength + 1 + digest.byteLength);
  input.set(domainBytes, 0);
  input[domainBytes.byteLength] = 0;
  input.set(digest, domainBytes.byteLength + 1);
  return input;
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
