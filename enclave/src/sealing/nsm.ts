import { randomBytes, createHash } from 'crypto';

const STUB = process.env['NSM_STUB'] === '1';

export function getEntropy(bytes: number): Buffer {
  if (STUB) return randomBytes(bytes);
  return callNsm('entropy', bytes);
}

export function getAttestationDoc(publicKeyDer: Buffer): Buffer {
  if (STUB) {
    return Buffer.concat([Buffer.alloc(48), publicKeyDer]);
  }
  return callNsm('attestation', publicKeyDer);
}

function callNsm(op: 'entropy', bytes: number): Buffer;
function callNsm(op: 'attestation', publicKeyDer: Buffer): Buffer;
function callNsm(op: string, arg: number | Buffer): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nsm = require('../native/nsm.node') as {
    getEntropy(n: number): Buffer;
    getAttestationDoc(key: Buffer): Buffer;
  };

  if (op === 'entropy') return nsm.getEntropy(arg as number);
  return nsm.getAttestationDoc(arg as Buffer);
}
