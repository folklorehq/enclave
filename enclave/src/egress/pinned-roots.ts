import { X509Certificate, createHash } from 'node:crypto';
import { rootCertificates } from 'node:tls';

export function spkiSha256Of(pem: string): string {
  const certificate = new X509Certificate(pem);
  return createHash('sha256')
    .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

export function selectPinnedRootPems(
  spkis: readonly string[],
  mismatchCode: string,
  pems: readonly string[] = rootCertificates,
): string[] {
  const wanted = new Set(spkis);
  const selected = new Map<string, string>();
  for (const pem of pems) {
    const spki = spkiSha256Of(pem);
    if (!wanted.has(spki)) continue;
    if (selected.has(spki)) throw new Error(mismatchCode);
    selected.set(spki, pem);
  }
  if (spkis.length === 0 || selected.size !== wanted.size || wanted.size !== spkis.length) {
    throw new Error(mismatchCode);
  }
  return [...selected.values()];
}
