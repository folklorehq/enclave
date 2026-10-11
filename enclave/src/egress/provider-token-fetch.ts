import { ProxyAgent } from 'undici';
import { EGRESS_PROXY_URL } from './proxy.js';

export type ProviderTokenOperation =
  | 'code'
  | 'refresh'
  | 'identity'
  | 'jira_resources'
  | 'github_installation'
  | 'github_user_code'
  | 'github_user_installations'
  | 'github_user_org_membership'
  | 'github_user_token_revoke';
export type ProviderRefreshCapability = 'supported' | 'unsupported';

export type ProviderTokenRequest =
  | {
      operation: 'code';
      clientId: string;
      clientSecret: string;
      code: string;
      callbackUri: string;
      pkceVerifier?: string;
    }
  | {
      operation: 'refresh';
      clientId: string;
      clientSecret: string;
      refreshToken: string;
    }
  | { operation: 'identity'; accessToken: string }
  | { operation: 'jira_resources'; accessToken: string }
  | {
      operation: 'github_installation';
      installationId: string;
      installationJwt: string;
    }
  | { operation: 'github_user_code'; clientId: string; clientSecret: string; code: string }
  | { operation: 'github_user_installations'; accessToken: string; page: number }
  | { operation: 'github_user_org_membership'; accessToken: string; organization: string }
  | {
      operation: 'github_user_token_revoke';
      clientId: string;
      clientSecret: string;
      accessToken: string;
    };

export interface VerifiedProviderConfig {
  kind: string;
  tokenEndpoint: string;
  identityEndpoint: string;
  githubInstallationEndpoint: string;
  oauthSecretRef: string;
  allowedHosts: readonly string[];
}

export interface ProviderTokenFetchOptions {
  fetchImpl?: typeof globalThis.fetch;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  timeoutMs?: number;
}

const DEFAULT_MAX_REQUEST_BYTES = 64 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
export const DEFAULT_PROVIDER_TIMEOUT_MS = 10_000;
const SUPPORTED_PROVIDER_KINDS = new Set([
  'slack',
  'github',
  'linear',
  'notion',
  'intercom',
  'jira',
  'google_drive',
  'gmail',
  'google_calendar',
]);
const LINEAR_IDENTITY_QUERY = 'query FolkloreOAuthIdentity { viewer { id organization { id } } }';
const NOTION_API_VERSION = '2026-03-11';
const JIRA_ACCESSIBLE_RESOURCES_ENDPOINT =
  'https://api.atlassian.com/oauth/token/accessible-resources';
const GITHUB_USER_INSTALLATIONS_PATH = '/user/installations';
const GITHUB_USER_ORG_MEMBERSHIP_PATH = '/user/memberships/orgs/';
export const GITHUB_LOGIN_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const GITHUB_CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const GITHUB_MEDIA_TYPE = 'application/vnd.github+json';
export const GITHUB_INSTALLATIONS_PAGE_SIZE = 100;

interface ExecutableProviderRequest {
  endpoint: string;
  query?: Readonly<Record<string, string>>;
  method: 'GET' | 'POST' | 'DELETE';
  acceptsNoContent?: boolean;
  headers: Record<string, string>;
  body?: string;
  allowedContentTypes: readonly string[];
}

interface BoundProviderRequest {
  executable: ExecutableProviderRequest;
  normalizedEndpoint: string;
  fetchImpl: typeof globalThis.fetch;
  maxRequestBytes: number;
  maxResponseBytes: number;
  timeoutMs: number;
}

/** Builds a zero-argument executor bound to one signed provider operation. */
export function createProviderTokenFetch(
  config: VerifiedProviderConfig,
  request: ProviderTokenRequest,
  options: ProviderTokenFetchOptions = {},
): () => Promise<Response> {
  assertSupportedProvider(config.kind);
  const executable = buildProviderRequest(config, request);
  const normalizedEndpoint = withQuery(
    normalizeEndpoint(executable.endpoint, config.allowedHosts),
    executable.query,
  );
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const maxRequestBytes = options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROVIDER_TIMEOUT_MS;

  return () =>
    executeProviderRequest({
      executable,
      normalizedEndpoint,
      fetchImpl,
      maxRequestBytes,
      maxResponseBytes,
      timeoutMs,
    });
}

// An enclave has no resolver: the host proxy resolves and gates; TLS server auth stops misdirection.
async function executeProviderRequest(bound: BoundProviderRequest): Promise<Response> {
  const bodyLength = bound.executable.body ? Buffer.byteLength(bound.executable.body) : 0;
  if (bodyLength > bound.maxRequestBytes) throw new ProviderEgressError();
  const proxy = new ProxyAgent({ uri: EGRESS_PROXY_URL });
  try {
    return await sendThroughProxy(bound, proxy);
  } catch (error) {
    throw classifyProviderFailure(error);
  } finally {
    await proxy.close().catch(() => undefined);
  }
}

async function sendThroughProxy(bound: BoundProviderRequest, proxy: ProxyAgent): Promise<Response> {
  const response = await bound.fetchImpl(bound.normalizedEndpoint, {
    method: bound.executable.method,
    headers: new Headers(bound.executable.headers),
    redirect: 'manual',
    signal: AbortSignal.timeout(bound.timeoutMs),
    dispatcher: proxy,
    ...(bound.executable.body ? { body: bound.executable.body } : {}),
  } as RequestInit & { dispatcher: ProxyAgent });
  if (bound.executable.acceptsNoContent && response.status === 204) {
    return new Response(null, { status: 204 });
  }
  return bufferProviderResponse(
    response,
    bound.executable.allowedContentTypes,
    bound.maxResponseBytes,
  );
}

function classifyProviderFailure(error: unknown): Error {
  if (error instanceof ProviderEgressError || error instanceof ProviderRejectedError) return error;
  return new ProviderEgressError();
}

async function bufferProviderResponse(
  response: Response,
  allowedContentTypes: readonly string[],
  maxResponseBytes: number,
): Promise<Response> {
  if (response.status >= 400 && response.status < 500) {
    throw new ProviderRejectedError(response.status);
  }
  if (response.status !== 200) throw new ProviderEgressError();
  const length = Number(response.headers.get('content-length') ?? 0);
  if (Number.isFinite(length) && length > maxResponseBytes) throw new ProviderEgressError();
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (!contentType || !allowedContentTypes.includes(contentType)) throw new ProviderEgressError();
  if (!response.body) return response;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.byteLength;
    if (size > maxResponseBytes) {
      await reader.cancel();
      throw new ProviderEgressError();
    }
    chunks.push(chunk.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Response(bytes, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export function refreshCapability(config: VerifiedProviderConfig): ProviderRefreshCapability {
  assertSupportedProvider(config.kind);
  return config.kind === 'intercom' ? 'unsupported' : 'supported';
}

export function assertSupportedProvider(kind: string): void {
  if (!SUPPORTED_PROVIDER_KINDS.has(kind)) throw new ProviderEgressError();
}

function buildProviderRequest(
  config: VerifiedProviderConfig,
  request: ProviderTokenRequest,
): ExecutableProviderRequest {
  if (request.operation === 'github_installation') {
    if (config.kind !== 'github') throw new ProviderEgressError();
    return {
      endpoint: resolveGitHubInstallationEndpoint(
        config.githubInstallationEndpoint,
        request.installationId,
      ),
      method: 'POST',
      headers: {
        accept: GITHUB_MEDIA_TYPE,
        authorization: `Bearer ${request.installationJwt}`,
      },
      allowedContentTypes: ['application/json'],
    };
  }
  if (isGitHubUserRequest(request)) {
    if (config.kind !== 'github') throw new ProviderEgressError();
    return gitHubUserRequest(config, request);
  }
  if (request.operation === 'identity') {
    return identityRequest(config, request.accessToken);
  }
  if (request.operation === 'jira_resources') {
    if (config.kind !== 'jira') throw new ProviderEgressError();
    return {
      endpoint: JIRA_ACCESSIBLE_RESOURCES_ENDPOINT,
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${request.accessToken}` },
      allowedContentTypes: ['application/json'],
    };
  }
  if (request.operation === 'refresh' && refreshCapability(config) === 'unsupported') {
    throw new ProviderEgressError();
  }
  return tokenRequest(config, request);
}

// No redirect_uri: the install-time code is redeemed against the App's registered callback.
function gitHubUserCodeRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'github_user_code' }>,
): ExecutableProviderRequest {
  return {
    endpoint: config.tokenEndpoint,
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: request.clientId,
      client_secret: request.clientSecret,
      code: request.code,
    }).toString(),
    allowedContentTypes: ['application/json'],
  };
}

function gitHubUserInstallationsRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'github_user_installations' }>,
): ExecutableProviderRequest {
  if (!Number.isSafeInteger(request.page) || request.page < 1) throw new ProviderEgressError();
  return {
    endpoint: new URL(GITHUB_USER_INSTALLATIONS_PATH, config.identityEndpoint).href,
    query: { per_page: String(GITHUB_INSTALLATIONS_PAGE_SIZE), page: String(request.page) },
    method: 'GET',
    headers: {
      accept: GITHUB_MEDIA_TYPE,
      authorization: `Bearer ${request.accessToken}`,
    },
    allowedContentTypes: ['application/json'],
  };
}

type GitHubUserRequest = Extract<ProviderTokenRequest, { operation: `github_user_${string}` }>;

function isGitHubUserRequest(request: ProviderTokenRequest): request is GitHubUserRequest {
  return request.operation.startsWith('github_user_');
}

function gitHubUserRequest(
  config: VerifiedProviderConfig,
  request: GitHubUserRequest,
): ExecutableProviderRequest {
  switch (request.operation) {
    case 'github_user_code':
      return gitHubUserCodeRequest(config, request);
    case 'github_user_installations':
      return gitHubUserInstallationsRequest(config, request);
    case 'github_user_org_membership':
      return gitHubUserOrgMembershipRequest(config, request);
    case 'github_user_token_revoke':
      return gitHubUserTokenRevokeRequest(config, request);
  }
}

function gitHubUserOrgMembershipRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'github_user_org_membership' }>,
): ExecutableProviderRequest {
  if (!GITHUB_LOGIN_PATTERN.test(request.organization)) throw new ProviderEgressError();
  return {
    endpoint: new URL(
      `${GITHUB_USER_ORG_MEMBERSHIP_PATH}${request.organization}`,
      config.identityEndpoint,
    ).href,
    method: 'GET',
    headers: { accept: GITHUB_MEDIA_TYPE, authorization: `Bearer ${request.accessToken}` },
    allowedContentTypes: ['application/json'],
  };
}

function gitHubUserTokenRevokeRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'github_user_token_revoke' }>,
): ExecutableProviderRequest {
  if (!GITHUB_CLIENT_ID_PATTERN.test(request.clientId)) throw new ProviderEgressError();
  const basic = Buffer.from(`${request.clientId}:${request.clientSecret}`).toString('base64');
  return {
    endpoint: new URL(`/applications/${request.clientId}/token`, config.identityEndpoint).href,
    method: 'DELETE',
    headers: {
      accept: GITHUB_MEDIA_TYPE,
      authorization: `Basic ${basic}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ access_token: request.accessToken }),
    allowedContentTypes: ['application/json'],
    acceptsNoContent: true,
  };
}

function withQuery(endpoint: string, query?: Readonly<Record<string, string>>): string {
  if (!query) return endpoint;
  const url = new URL(endpoint);
  url.search = new URLSearchParams(query).toString();
  return url.href;
}

function identityRequest(
  config: VerifiedProviderConfig,
  accessToken: string,
): ExecutableProviderRequest {
  const headers: Record<string, string> = {
    accept: config.kind === 'github' ? GITHUB_MEDIA_TYPE : 'application/json',
    authorization: `Bearer ${accessToken}`,
  };
  if (config.kind === 'notion') headers['notion-version'] = NOTION_API_VERSION;
  if (config.kind === 'linear') {
    headers['content-type'] = 'application/json';
    return {
      endpoint: config.identityEndpoint,
      method: 'POST',
      headers,
      body: JSON.stringify({ query: LINEAR_IDENTITY_QUERY }),
      allowedContentTypes: ['application/json'],
    };
  }
  return {
    endpoint: config.identityEndpoint,
    method: 'GET',
    headers,
    allowedContentTypes: ['application/json'],
  };
}

function tokenRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'code' | 'refresh' }>,
): ExecutableProviderRequest {
  if (config.kind === 'notion') return notionTokenRequest(config, request);
  if (config.kind === 'jira') return jiraTokenRequest(config, request);
  const body = new URLSearchParams();
  body.set('client_id', request.clientId);
  body.set('client_secret', request.clientSecret);
  if (request.operation === 'code') {
    body.set('code', request.code);
    if (config.kind !== 'intercom') body.set('redirect_uri', request.callbackUri);
    if (config.kind === 'linear') body.set('grant_type', 'authorization_code');
    if (request.pkceVerifier) body.set('code_verifier', request.pkceVerifier);
  } else {
    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', request.refreshToken);
  }
  return {
    endpoint: config.tokenEndpoint,
    method: 'POST',
    headers: {
      accept: 'application/json, application/x-www-form-urlencoded',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
    allowedContentTypes: ['application/json', 'application/x-www-form-urlencoded'],
  };
}

function notionTokenRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'code' | 'refresh' }>,
): ExecutableProviderRequest {
  const headers = {
    authorization: `Basic ${Buffer.from(`${request.clientId}:${request.clientSecret}`).toString('base64')}`,
    'notion-version': NOTION_API_VERSION,
  };
  if (request.operation === 'code') {
    return jsonTokenRequest(
      config,
      {
        grant_type: 'authorization_code',
        code: request.code,
        redirect_uri: request.callbackUri,
      },
      headers,
    );
  }
  return jsonTokenRequest(
    config,
    { grant_type: 'refresh_token', refresh_token: request.refreshToken },
    headers,
  );
}

function jiraTokenRequest(
  config: VerifiedProviderConfig,
  request: Extract<ProviderTokenRequest, { operation: 'code' | 'refresh' }>,
): ExecutableProviderRequest {
  const credentials = { client_id: request.clientId, client_secret: request.clientSecret };
  const payload =
    request.operation === 'code'
      ? {
          ...credentials,
          grant_type: 'authorization_code',
          code: request.code,
          redirect_uri: request.callbackUri,
        }
      : { ...credentials, grant_type: 'refresh_token', refresh_token: request.refreshToken };
  return jsonTokenRequest(config, payload);
}

function jsonTokenRequest(
  config: VerifiedProviderConfig,
  payload: Record<string, string>,
  extraHeaders: Record<string, string> = {},
): ExecutableProviderRequest {
  return {
    endpoint: config.tokenEndpoint,
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json', ...extraHeaders },
    body: JSON.stringify(payload),
    allowedContentTypes: ['application/json'],
  };
}

export function resolveGitHubInstallationEndpoint(
  template: string,
  installationId: string,
): string {
  if (!/^[0-9]+$/.test(installationId)) throw new ProviderEgressError();
  const matches = template.match(/\{installationId\}/g);
  if (matches?.length !== 1) throw new ProviderEgressError();
  const endpoint = template.replace('{installationId}', installationId);
  return endpoint;
}

export class ProviderEgressError extends Error {
  constructor() {
    super('provider_egress_denied');
    this.name = 'ProviderEgressError';
  }
}

export class ProviderRejectedError extends Error {
  readonly status: number;

  constructor(status: number) {
    super('provider_rejected');
    this.name = 'ProviderRejectedError';
    this.status = status;
  }
}

export function normalizeEndpoint(value: string, allowedHosts: readonly string[]): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProviderEgressError();
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    !allowedHosts.includes(url.hostname.toLowerCase())
  ) {
    throw new ProviderEgressError();
  }
  if (url.href !== value) throw new ProviderEgressError();
  return url.href;
}
