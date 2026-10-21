import {
  OPENAI_EMBED_ROUTE_STATE,
  type OpenAIEmbedRouteState,
} from './openai/openai-embed-route-state.js';

export interface EmbeddingSpace {
  readonly id: string;
  readonly model: string;
  readonly dimensions: number;
}

export const LEGACY_EMBEDDING_SPACE: EmbeddingSpace = Object.freeze({
  id: 'qwen3-embedding-8b-d4096',
  model: 'qwen/qwen3-embedding-8b',
  dimensions: 4096,
});

export const OPENAI_EMBEDDING_SPACE: EmbeddingSpace = Object.freeze({
  id: 'text-embedding-3-large-d1536',
  model: 'text-embedding-3-large',
  dimensions: 1536,
});

/** An invalid route maps to the OpenAI space, so it can never reopen the legacy index. */
export function embeddingSpaceFor(state: OpenAIEmbedRouteState): EmbeddingSpace {
  return state.kind === 'disabled' ? LEGACY_EMBEDDING_SPACE : OPENAI_EMBEDDING_SPACE;
}

export function isLegacyEmbeddingSpace(space: EmbeddingSpace): boolean {
  return space.id === LEGACY_EMBEDDING_SPACE.id;
}

export const ACTIVE_EMBEDDING_SPACE: EmbeddingSpace = embeddingSpaceFor(OPENAI_EMBED_ROUTE_STATE);
export const ACTIVE_EMBEDDING_SPACE_IS_LEGACY: boolean =
  isLegacyEmbeddingSpace(ACTIVE_EMBEDDING_SPACE);

export const EMBEDDING_SPACE_REQUIRES_SHARED_POOL = 'embedding_space_requires_shared_pool';

/** Only a shared pool can reach the OpenAI embed route, so any other deployment fails at boot instead of dead-lettering later. */
export function assertEmbeddingSpaceDeployable(input: {
  readonly sharedPool: boolean;
  readonly space: EmbeddingSpace;
}): void {
  if (input.sharedPool || isLegacyEmbeddingSpace(input.space)) return;
  throw new Error(EMBEDDING_SPACE_REQUIRES_SHARED_POOL);
}
