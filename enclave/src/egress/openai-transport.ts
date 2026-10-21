import { selectOpenAIRootPems } from './openai-roots.js';
import { createPinnedOriginTransport, type PinnedOriginPolicy } from './pinned-origin-transport.js';

export const OPENAI_ORIGIN = 'https://api.openai.com';
export const OPENAI_EMBEDDINGS_PATH = '/v1/embeddings';
export const OPENAI_MODEL_PATH = '/v1/models/text-embedding-3-large';
export const OPENAI_TRANSPORT_CLOSED = 'openai_transport_closed';
export const OPENAI_REQUEST_REFUSED = 'openai_request_refused';

const ALLOWED_HEADERS: readonly string[] = [
  'authorization',
  'content-type',
  'accept',
  'user-agent',
];
const NO_HEADER_PREFIXES: readonly string[] = [];

export interface OpenAITransport {
  readonly fetch: typeof globalThis.fetch;
  close(): Promise<void>;
}

export interface OpenAITransportOptions {
  readonly caPems?: readonly string[];
  readonly proxyPort?: number;
  readonly fetchImpl?: typeof globalThis.fetch;
}

const OPENAI_POLICY: PinnedOriginPolicy = {
  origin: OPENAI_ORIGIN,
  permitted: (method, path) =>
    (path === OPENAI_EMBEDDINGS_PATH && method === 'POST') ||
    (path === OPENAI_MODEL_PATH && method === 'GET'),
  headerAllowlist: ALLOWED_HEADERS,
  headerPrefixAllowlist: NO_HEADER_PREFIXES,
  refusedCode: OPENAI_REQUEST_REFUSED,
  closedCode: OPENAI_TRANSPORT_CLOSED,
};

export function createOpenAITransport(options: OpenAITransportOptions = {}): OpenAITransport {
  return createPinnedOriginTransport({
    policy: OPENAI_POLICY,
    caPems: options.caPems ?? selectOpenAIRootPems(),
    ...(options.proxyPort === undefined ? {} : { proxyPort: options.proxyPort }),
    ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
  });
}
