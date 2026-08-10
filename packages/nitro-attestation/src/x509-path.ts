import { timingSafeEqual, type KeyObject, X509Certificate } from 'node:crypto'; // gitleaks:allow
import * as asn1js from 'asn1js';
import { BasicConstraints, Certificate } from 'pkijs';

import { NitroAttestationError } from './failures.js';

const allowedCriticalExtensionIds = new Set(['2.5.29.15', '2.5.29.19']);
const digitalSignatureUsage = 0x80;
const keyCertSignUsage = 0x04;

interface ParsedCertificate {
  node: X509Certificate;
  policy: Certificate;
}

function failInvalidPath(): never {
  throw new NitroAttestationError('invalid_certificate_path');
}

function parseCertificate(der: Uint8Array): ParsedCertificate {
  try {
    const decoded = asn1js.fromBER(der);
    if (decoded.offset !== der.byteLength) {
      return failInvalidPath();
    }
    const policy = new Certificate({ schema: decoded.result });
    const canonicalDer = new Uint8Array(policy.toSchema().toBER(false));
    if (canonicalDer.byteLength !== der.byteLength || !timingSafeEqual(canonicalDer, der)) {
      return failInvalidPath();
    }
    return { node: new X509Certificate(der), policy };
  } catch {
    return failInvalidPath();
  }
}

function hasKeyUsage(certificate: Certificate, usage: number): boolean {
  const keyUsage = certificate.extensions?.find(
    (extension) => extension.extnID === '2.5.29.15',
  )?.parsedValue;
  return (
    keyUsage instanceof asn1js.BitString &&
    ((keyUsage.valueBlock.valueHexView[0] ?? 0) & usage) !== 0
  );
}

function validateValidity(chain: X509Certificate[], verificationTime: Date): void {
  const timestamp = verificationTime.getTime();
  if (
    !Number.isFinite(timestamp) ||
    chain.some(
      (certificate) =>
        timestamp < Date.parse(certificate.validFrom) ||
        timestamp > Date.parse(certificate.validTo),
    )
  ) {
    failInvalidPath();
  }
}

function validateCertificateAuthorities(issuers: Certificate[]): void {
  if (
    issuers.some((certificate, index) => {
      const basicConstraints = certificate.extensions?.find(
        (extension) => extension.extnID === '2.5.29.19',
      )?.parsedValue;
      if (!(basicConstraints instanceof BasicConstraints) || !basicConstraints.cA) {
        return true;
      }
      const pathLength = basicConstraints.pathLenConstraint;
      return (
        !hasKeyUsage(certificate, keyCertSignUsage) ||
        (pathLength !== undefined &&
          (typeof pathLength !== 'number' || issuers.length - index - 1 > pathLength))
      );
    })
  ) {
    failInvalidPath();
  }
}

function validateLeafPolicy(leaf: Certificate): void {
  const basicConstraints = leaf.extensions?.find(
    (extension) => extension.extnID === '2.5.29.19',
  )?.parsedValue;
  if (
    !(basicConstraints instanceof BasicConstraints) ||
    basicConstraints.cA ||
    !hasKeyUsage(leaf, digitalSignatureUsage)
  ) {
    failInvalidPath();
  }
}

function validateCriticalExtensions(chain: Certificate[]): void {
  if (
    chain.some((certificate) =>
      certificate.extensions?.some(
        (extension) => extension.critical && !allowedCriticalExtensionIds.has(extension.extnID),
      ),
    )
  ) {
    failInvalidPath();
  }
}

function validateOrderedSignatures(chain: X509Certificate[]): void {
  for (let index = 1; index < chain.length; index += 1) {
    const issuer = chain[index - 1];
    const certificate = chain[index];
    if (
      issuer === undefined ||
      certificate === undefined ||
      !certificate.checkIssued(issuer) ||
      !certificate.verify(issuer.publicKey)
    ) {
      failInvalidPath();
    }
  }
}

function getP384LeafKey(leaf: X509Certificate): KeyObject {
  const publicKey = leaf.publicKey;
  if (
    publicKey.asymmetricKeyType !== 'ec' ||
    publicKey.asymmetricKeyDetails?.namedCurve !== 'secp384r1'
  ) {
    failInvalidPath();
  }
  return publicKey;
}

export interface CertificatePathInput {
  leafDer: Uint8Array;
  cabundle: Uint8Array[];
  trustedRootDer: Uint8Array;
  verificationTime: Date;
}

export function verifyCertificatePath(input: CertificatePathInput): KeyObject {
  const root = input.cabundle[0];
  if (
    root === undefined ||
    root.byteLength !== input.trustedRootDer.byteLength ||
    !timingSafeEqual(root, input.trustedRootDer)
  ) {
    failInvalidPath();
  }
  const parsed = [...input.cabundle, input.leafDer].map(parseCertificate);
  const chain = parsed.map((certificate) => certificate.node);
  const policyChain = parsed.map((certificate) => certificate.policy);
  const policyLeaf = policyChain.at(-1);
  if (policyLeaf === undefined) {
    failInvalidPath();
  }
  const leaf = chain.at(-1);
  if (leaf === undefined) {
    failInvalidPath();
  }
  validateValidity(chain, input.verificationTime);
  validateCertificateAuthorities(policyChain.slice(0, -1));
  validateLeafPolicy(policyLeaf);
  validateCriticalExtensions(policyChain);
  validateOrderedSignatures(chain);
  return getP384LeafKey(leaf);
}
