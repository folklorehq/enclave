import { CLAUDE_ROUTE_MODEL_IDS } from '@folklore/contracts';
import { selectAnthropicRootPems } from './anthropic-roots.js';
import { createPinnedOriginTransport, type PinnedOriginPolicy } from './pinned-origin-transport.js';

export const ANTHROPIC_ORIGIN = 'https://api.anthropic.com';
const ANTHROPIC_MESSAGES_PATH = '/v1/messages';
const BATCHES_PATH = '/v1/messages/batches';
const BATCH_PATH_PATTERN =
  /^\/v1\/messages\/batches\/(msgbatch_[A-Za-z0-9]{1,64})(\/results|\/cancel)?$/;
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

export type AnthropicIdentity = 'synchronous' | 'batch';

export interface AnthropicTransportOptions {
  readonly identity?: AnthropicIdentity;
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
    permitted: (method, path) =>
      isPermittedPath(path, method, allowedModels, options.identity ?? 'synchronous'),
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
  identity: AnthropicIdentity,
): boolean {
  if (path.startsWith(ANTHROPIC_MODELS_PATH_PREFIX)) {
    return method === 'GET' && allowedModels.has(path.slice(ANTHROPIC_MODELS_PATH_PREFIX.length));
  }
  return identity === 'batch' ? isBatchPath(path, method) : isSynchronousPath(path, method);
}

function isSynchronousPath(path: string, method: string): boolean {
  return path === ANTHROPIC_MESSAGES_PATH && method === 'POST';
}

function isBatchPath(path: string, method: string): boolean {
  if (path === BATCHES_PATH) return method === 'POST';
  const match = BATCH_PATH_PATTERN.exec(path);
  if (match === null) return false;
  const [, , action] = match;
  if (action === '/results') return method === 'GET';
  if (action === '/cancel') return method === 'POST';
  return method === 'GET' || method === 'DELETE';
}
