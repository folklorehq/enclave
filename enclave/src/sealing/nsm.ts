/**
 * NSM (Nitro Secure Module) interface.
 *
 * In production the enclave communicates with the NSM via ioctl on /dev/nsm.
 * Set NSM_STUB=1 in dev to skip hardware calls — crypto.randomBytes() is used
 * for entropy and a minimal CBOR attestation doc is returned.
 */
import { randomBytes, createHash } from 'crypto';

const STUB = process.env['NSM_STUB'] === '1';

export function getEntropy(bytes: number): Buffer {
  if (STUB) return randomBytes(bytes);

  // Production: delegate to NSM via native addon or ioctl helper.
  // The NSM provides hardware-seeded entropy superior to /dev/urandom.
  // For ephemeral key generation, randomBytes() would be acceptable —
  // but we use NSM entropy for the master key on first boot.
  return callNsm('entropy', bytes);
}

export function getAttestationDoc(publicKeyDer: Buffer): Buffer {
  if (STUB) {
    // Minimal structure — seal.ts only reads this opaquely to pass to KMS.
    // KMS in stub mode doesn't enforce PCR conditions.
    return Buffer.concat([Buffer.alloc(48), publicKeyDer]);
  }

  return callNsm('attestation', publicKeyDer);
}

function callNsm(op: 'entropy', bytes: number): Buffer;
function callNsm(op: 'attestation', publicKeyDer: Buffer): Buffer;
function callNsm(op: string, arg: number | Buffer): Buffer {
  // Native helper is a thin C shim that opens /dev/nsm and issues the ioctl.
  // Built as part of the enclave Docker image from enclave/native/nsm.c.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nsm = require('../native/nsm.node') as {
    getEntropy(n: number): Buffer;
    getAttestationDoc(key: Buffer): Buffer;
  };

  if (op === 'entropy') return nsm.getEntropy(arg as number);
  return nsm.getAttestationDoc(arg as Buffer);
}
