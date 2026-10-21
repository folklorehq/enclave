import { ProxyAgent, fetch as undiciFetch } from 'undici';
import { EGRESS_PROXY_PORT } from './proxy.js';

const TLS_MIN_VERSION = 'TLSv1.2';

export interface PinnedOriginPolicy {
  readonly origin: string;
  permitted(method: string, path: string): boolean;
  readonly headerAllowlist: readonly string[];
  readonly headerPrefixAllowlist: readonly string[];
  readonly refusedCode: string;
  readonly closedCode: string;
}

export interface PinnedOriginTransport {
  readonly fetch: typeof globalThis.fetch;
  close(): Promise<void>;
}

export interface PinnedOriginTransportInput {
  readonly policy: PinnedOriginPolicy;
  readonly caPems: readonly string[];
  readonly proxyPort?: number;
  readonly fetchImpl?: typeof globalThis.fetch;
}

interface SuppliedRequest {
  readonly url: URL;
  readonly method: string;
  readonly headers: Headers;
}

export function createPinnedOriginTransport(
  input: PinnedOriginTransportInput,
): PinnedOriginTransport {
  const { policy } = input;
  const fetchImpl = input.fetchImpl ?? (undiciFetch as unknown as typeof globalThis.fetch);
  const dispatcher = new ProxyAgent({
    uri: `http://localhost:${input.proxyPort ?? EGRESS_PROXY_PORT}`,
    requestTls: { ca: [...input.caPems], minVersion: TLS_MIN_VERSION },
  });
  let closed = false;
  let closing: Promise<void> | undefined;
  const transportFetch: typeof globalThis.fetch = async (request, init) => {
    if (closed) throw new Error(policy.closedCode);
    assertPermitted(supplied(request, init), policy);
    return fetchImpl(request, { ...init, redirect: 'error', dispatcher } as RequestInit & {
      dispatcher: ProxyAgent;
    });
  };
  return {
    fetch: transportFetch,
    close: () => {
      closed = true;
      return (closing ??= dispatcher.close());
    },
  };
}

function supplied(
  input: Parameters<typeof fetch>[0],
  init: RequestInit | undefined,
): SuppliedRequest {
  const url = new URL(
    typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
  );
  const inherited = input instanceof Request ? input : undefined;
  const headers = new Headers(inherited?.headers);
  new Headers(init?.headers).forEach((value, name) => headers.set(name, value));
  return { url, method: (init?.method ?? inherited?.method ?? 'GET').toUpperCase(), headers };
}

function assertPermitted(request: SuppliedRequest, policy: PinnedOriginPolicy): void {
  const { url } = request;
  const permitted =
    url.origin === policy.origin &&
    url.search === '' &&
    url.hash === '' &&
    url.username === '' &&
    url.password === '' &&
    onlyAllowedHeaders(request.headers, policy) &&
    policy.permitted(request.method, url.pathname);
  if (!permitted) throw new Error(policy.refusedCode);
}

function onlyAllowedHeaders(headers: Headers, policy: PinnedOriginPolicy): boolean {
  const allowed = new Set(policy.headerAllowlist);
  return [...headers.keys()].every(
    (name) =>
      allowed.has(name) || policy.headerPrefixAllowlist.some((prefix) => name.startsWith(prefix)),
  );
}
