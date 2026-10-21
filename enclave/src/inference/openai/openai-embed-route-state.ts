import {
  OPENAI_EMBED_ROUTE_IDENTITY,
  type OpenAIEmbedRouteIdentity,
} from './openai-embed-route-config.js';

export const OPENAI_EMBED_MODEL = 'text-embedding-3-large';
export const OPENAI_EMBED_DIMENSIONS = 1536;
export const OPENAI_EMBED_ROUTE_INVALID_ALARM = 'openai_embed_route_invalid';

const SHA256_HEX = /^[0-9a-f]{64}$/;

export type OpenAIEmbedRouteInvalidReason =
  | 'organization_hash_malformed'
  | 'project_hash_malformed'
  | 'model_unsupported'
  | 'dimensions_unsupported';

export type OpenAIEmbedRouteState =
  | { readonly kind: 'disabled' }
  | { readonly kind: 'enabled'; readonly identity: OpenAIEmbedRouteIdentity }
  | { readonly kind: 'invalid'; readonly reason: OpenAIEmbedRouteInvalidReason };

/** Pure and total: a malformed literal becomes `invalid`, never an import-time throw. */
export function openaiEmbedRouteState(identity: OpenAIEmbedRouteIdentity): OpenAIEmbedRouteState {
  if (identity.enabled !== true) return { kind: 'disabled' };
  const reason = invalidReasonOf(identity);
  return reason === undefined ? { kind: 'enabled', identity } : { kind: 'invalid', reason };
}

function invalidReasonOf(
  identity: OpenAIEmbedRouteIdentity,
): OpenAIEmbedRouteInvalidReason | undefined {
  if (!isSha256Hex(identity.organizationIdSha256)) return 'organization_hash_malformed';
  if (identity.projectIdSha256 !== '' && !isSha256Hex(identity.projectIdSha256)) {
    return 'project_hash_malformed';
  }
  if (identity.model !== OPENAI_EMBED_MODEL) return 'model_unsupported';
  if (identity.dimensions !== OPENAI_EMBED_DIMENSIONS) return 'dimensions_unsupported';
  return undefined;
}

function isSha256Hex(value: unknown): boolean {
  return typeof value === 'string' && SHA256_HEX.test(value);
}

export const OPENAI_EMBED_ROUTE_STATE: OpenAIEmbedRouteState = Object.freeze(
  openaiEmbedRouteState(OPENAI_EMBED_ROUTE_IDENTITY),
);
