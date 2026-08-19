import { createHash } from 'node:crypto';
import { checkServerIdentity } from 'node:tls';
import { matchesSpkiPin } from '@folklore/utils';
import type { InferenceTrustPolicyV1 } from '@folklore/contracts';
import { ProxyAgent } from 'undici';
import { EGRESS_PROXY_PORT } from './proxy.js';

type InferenceTransportPolicy = Pick<InferenceTrustPolicyV1, 'origin' | 'route' | 'tlsSpkiSha256'>;

export function createPinnedInferenceFetch(
  policy: InferenceTransportPolicy,
  fetchImpl: typeof globalThis.fetch = globalThis.fetch,
): typeof globalThis.fetch {
  const dispatcher = new ProxyAgent({
    uri: `http://localhost:${EGRESS_PROXY_PORT}`,
    requestTls: {
      checkServerIdentity: (hostname, certificate) =>
        verifyInferenceCertificate(hostname, certificate, policy.tlsSpkiSha256),
    },
  });

  return async (input, init) => {
    const supplied =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(supplied);
    const routePrefix = policy.route === '/' ? '/' : `${policy.route}/`;
    if (
      url.origin !== policy.origin ||
      (url.pathname !== policy.route && !url.pathname.startsWith(routePrefix))
    ) {
      throw new Error('inference_origin_mismatch');
    }
    return fetchImpl(input, {
      ...init,
      redirect: 'error',
      ...(fetchImpl === globalThis.fetch ? { dispatcher } : {}),
    } as RequestInit & { dispatcher?: ProxyAgent });
  };
}

function verifyInferenceCertificate(
  hostname: string,
  certificate: Parameters<typeof checkServerIdentity>[1],
  expectedPins: readonly string[],
): Error | undefined {
  const tlsError = checkServerIdentity(hostname, certificate);
  if (tlsError) return tlsError;
  if (!certificate.pubkey) return new Error('inference_spki_unavailable');
  const actualPin = createHash('sha256').update(certificate.pubkey).digest('hex');
  return matchesSpkiPin(expectedPins, actualPin)
    ? undefined
    : new Error('inference_spki_pin_mismatch');
}
