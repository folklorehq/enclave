import { X509Certificate, createHash } from 'node:crypto';
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
  return createPinnedInferenceTransport(policy, fetchImpl).fetch;
}

export function createPinnedInferenceTransport(
  policy: InferenceTransportPolicy,
  fetchImpl: typeof globalThis.fetch = globalThis.fetch,
): { fetch: typeof globalThis.fetch; close: () => Promise<void> } {
  const origin = policy.origin;
  const route = policy.route;
  const pins = [...policy.tlsSpkiSha256];
  const dispatcher = new ProxyAgent({
    uri: `http://localhost:${EGRESS_PROXY_PORT}`,
    requestTls: {
      checkServerIdentity: (hostname, certificate) =>
        verifyInferenceCertificate(hostname, certificate, pins),
    },
  });

  let closed = false;
  let closing: Promise<void> | undefined;
  const fetch: typeof globalThis.fetch = async (input, init) => {
    if (closed) throw new Error('inference_transport_closed');
    const supplied =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(supplied);
    const routePrefix = route === '/' ? '/' : `${route}/`;
    if (
      url.origin !== origin ||
      (url.pathname !== route && !url.pathname.startsWith(routePrefix))
    ) {
      throw new Error('inference_origin_mismatch');
    }
    return fetchImpl(input, {
      ...init,
      redirect: 'error',
      ...(fetchImpl === globalThis.fetch ? { dispatcher } : {}),
    } as RequestInit & { dispatcher?: ProxyAgent });
  };
  return {
    fetch,
    close: () => {
      closed = true;
      return (closing ??= dispatcher.close());
    },
  };
}

export function verifyInferenceCertificate(
  hostname: string,
  certificate: Parameters<typeof checkServerIdentity>[1],
  expectedPins: readonly string[],
): Error | undefined {
  const tlsError = checkServerIdentity(hostname, certificate);
  if (tlsError) return tlsError;
  const spki = subjectPublicKeyInfoDer(certificate);
  if (!spki) return new Error('inference_spki_unavailable');
  const actualPin = createHash('sha256').update(spki).digest('hex');
  return matchesSpkiPin(expectedPins, actualPin)
    ? undefined
    : new Error('inference_spki_pin_mismatch');
}

// Node's `certificate.pubkey` is the bare EC point for ECDSA keys, not the SPKI the pin is taken over.
function subjectPublicKeyInfoDer(
  certificate: Parameters<typeof checkServerIdentity>[1],
): Buffer | undefined {
  if (!certificate.raw) return undefined;
  try {
    return new X509Certificate(certificate.raw).publicKey.export({ type: 'spki', format: 'der' });
  } catch {
    return undefined;
  }
}
