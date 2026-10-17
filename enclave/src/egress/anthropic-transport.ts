import { CLAUDE_ZDR_MODEL_IDS } from '@folklore/contracts';
import { ProxyAgent, fetch as undiciFetch } from 'undici';
import { selectAnthropicRootPems } from './anthropic-roots.js';
import { EGRESS_PROXY_PORT } from './proxy.js';

export const ANTHROPIC_ORIGIN = 'https://api.anthropic.com';
const ANTHROPIC_MESSAGES_PATH = '/v1/messages';
export const ANTHROPIC_MODELS_PATH_PREFIX = '/v1/models/';
export const ANTHROPIC_TRANSPORT_CLOSED = 'anthropic_transport_closed';
export const ANTHROPIC_REQUEST_REFUSED = 'anthropic_request_refused';

const ALLOWED_HEADERS: ReadonlySet<string> = new Set([
  'x-api-key',
  'anthropic-version',
  'content-type',
  'accept',
  'user-agent',
]);
const ALLOWED_HEADER_PREFIX = 'x-stainless-';
const TLS_MIN_VERSION = 'TLSv1.2';

export interface AnthropicTransport {
  readonly fetch: typeof globalThis.fetch;
  close(): Promise<void>;
}

export interface AnthropicTransportOptions {
  readonly allowedModels?: readonly string[];
  readonly caPems?: readonly string[];
  readonly proxyPort?: number;
  readonly fetchImpl?: typeof globalThis.fetch;
}

interface SuppliedRequest {
  readonly url: URL;
  readonly method: string;
  readonly headers: Headers;
}

export function createAnthropicTransport(
  options: AnthropicTransportOptions = {},
): AnthropicTransport {
  const allowedModels = new Set<string>(options.allowedModels ?? CLAUDE_ZDR_MODEL_IDS);
  const ca = [...(options.caPems ?? selectAnthropicRootPems())];
  const fetchImpl = options.fetchImpl ?? (undiciFetch as unknown as typeof globalThis.fetch);
  const dispatcher = new ProxyAgent({
    uri: `http://localhost:${options.proxyPort ?? EGRESS_PROXY_PORT}`,
    requestTls: { ca, minVersion: TLS_MIN_VERSION },
  });
  let closed = false;
  let closing: Promise<void> | undefined;
  const transportFetch: typeof globalThis.fetch = async (input, init) => {
    if (closed) throw new Error(ANTHROPIC_TRANSPORT_CLOSED);
    assertPermitted(supplied(input, init), allowedModels);
    return fetchImpl(input, { ...init, redirect: 'error', dispatcher } as RequestInit & {
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

function assertPermitted(request: SuppliedRequest, allowedModels: ReadonlySet<string>): void {
  const { url } = request;
  const permitted =
    url.origin === ANTHROPIC_ORIGIN &&
    url.search === '' &&
    url.hash === '' &&
    url.username === '' &&
    url.password === '' &&
    onlyAllowedHeaders(request.headers) &&
    isPermittedPath(url.pathname, request.method, allowedModels);
  if (!permitted) throw new Error(ANTHROPIC_REQUEST_REFUSED);
}

function onlyAllowedHeaders(headers: Headers): boolean {
  return [...headers.keys()].every(
    (name) => ALLOWED_HEADERS.has(name) || name.startsWith(ALLOWED_HEADER_PREFIX),
  );
}

function isPermittedPath(
  path: string,
  method: string,
  allowedModels: ReadonlySet<string>,
): boolean {
  if (path === ANTHROPIC_MESSAGES_PATH) return method === 'POST';
  if (!path.startsWith(ANTHROPIC_MODELS_PATH_PREFIX)) return false;
  return method === 'GET' && allowedModels.has(path.slice(ANTHROPIC_MODELS_PATH_PREFIX.length));
}
