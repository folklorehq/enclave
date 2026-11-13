import { createPinnedOriginTransport, type PinnedOriginPolicy } from './pinned-origin-transport.js';
import { selectTypeSafeRootPems } from './typesafe-roots.js';

export const TYPESAFE_ORIGIN = 'https://api.typesafe.ai';
export const TYPESAFE_DECIDE_PATH = '/v1/systemone';
export const TYPESAFE_MODELS_PATH = '/v1/models';
export const TYPESAFE_REQUEST_REFUSED = 'typesafe_request_refused';
export const TYPESAFE_TRANSPORT_CLOSED = 'typesafe_transport_closed';

const ALLOWED_HEADERS: readonly string[] = [
  'authorization',
  'content-type',
  'accept',
  'user-agent',
];
const NO_HEADER_PREFIXES: readonly string[] = [];

export interface TypeSafeTransport {
  readonly fetch: typeof globalThis.fetch;
  close(): Promise<void>;
}

export interface TypeSafeTransportOptions {
  readonly caPems?: readonly string[];
  readonly proxyPort?: number;
  readonly fetchImpl?: typeof globalThis.fetch;
}

const TYPESAFE_POLICY: PinnedOriginPolicy = {
  origin: TYPESAFE_ORIGIN,
  permitted: (method, path) =>
    (path === TYPESAFE_DECIDE_PATH && method === 'POST') ||
    (path === TYPESAFE_MODELS_PATH && method === 'GET'),
  headerAllowlist: ALLOWED_HEADERS,
  headerPrefixAllowlist: NO_HEADER_PREFIXES,
  refusedCode: TYPESAFE_REQUEST_REFUSED,
  closedCode: TYPESAFE_TRANSPORT_CLOSED,
};

export function createTypeSafeTransport(options: TypeSafeTransportOptions = {}): TypeSafeTransport {
  return createPinnedOriginTransport({
    policy: TYPESAFE_POLICY,
    caPems: options.caPems ?? selectTypeSafeRootPems(),
    ...(options.proxyPort === undefined ? {} : { proxyPort: options.proxyPort }),
    ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
  });
}
