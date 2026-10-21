import { CLAUDE_ROUTE_MODEL_IDS } from '@folklore/contracts';
import { selectAnthropicRootPems } from './anthropic-roots.js';
import { createPinnedOriginTransport, type PinnedOriginPolicy } from './pinned-origin-transport.js';

export const ANTHROPIC_ORIGIN = 'https://api.anthropic.com';
const ANTHROPIC_MESSAGES_PATH = '/v1/messages';
export const ANTHROPIC_MODELS_PATH_PREFIX = '/v1/models/';
export const ANTHROPIC_TRANSPORT_CLOSED = 'anthropic_transport_closed';
export const ANTHROPIC_REQUEST_REFUSED = 'anthropic_request_refused';

const ALLOWED_HEADERS: readonly string[] = [
  'x-api-key',
  'anthropic-version',
  'content-type',
  'accept',
  'user-agent',
];
const ALLOWED_HEADER_PREFIXES: readonly string[] = ['x-stainless-'];

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

export function createAnthropicTransport(
  options: AnthropicTransportOptions = {},
): AnthropicTransport {
  const allowedModels = new Set<string>(options.allowedModels ?? CLAUDE_ROUTE_MODEL_IDS);
  const policy: PinnedOriginPolicy = {
    origin: ANTHROPIC_ORIGIN,
    permitted: (method, path) => isPermittedPath(path, method, allowedModels),
    headerAllowlist: ALLOWED_HEADERS,
    headerPrefixAllowlist: ALLOWED_HEADER_PREFIXES,
    refusedCode: ANTHROPIC_REQUEST_REFUSED,
    closedCode: ANTHROPIC_TRANSPORT_CLOSED,
  };
  return createPinnedOriginTransport({
    policy,
    caPems: options.caPems ?? selectAnthropicRootPems(),
    ...(options.proxyPort === undefined ? {} : { proxyPort: options.proxyPort }),
    ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
  });
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
