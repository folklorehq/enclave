import type { InferenceUsageSink } from '@folklore/inference';
import type { AttestedSsmParameterReader } from '../../attestation/AttestedSsmParameterReader.js';
import { createOpenAITransport, type OpenAITransport } from '../../egress/openai-transport.js';
import { OpenAICredentialSource, type OpenAICredentialManifest } from './OpenAICredentialSource.js';
import { OpenAIEmbeddingsBackend } from './OpenAIEmbeddingsBackend.js';
import { OpenAIEmbedRouteError } from './openai-embed-errors.js';
import { mapOpenAITransportError } from './openai-error-map.js';
import {
  OPENAI_EMBED_DIMENSIONS,
  OPENAI_EMBED_MODEL,
  type OpenAIEmbedRouteState,
} from './openai-embed-route-state.js';

export const OPENAI_EMBED_CACHE_LABEL = `openai/${OPENAI_EMBED_MODEL}@${OPENAI_EMBED_DIMENSIONS}`;

export interface EmbeddingProvider {
  embed(text: string): Promise<number[]>;
  readonly cacheLabel: string;
}

export interface OpenAIEmbedRouteCompositionDeps {
  readonly state: OpenAIEmbedRouteState;
  readonly reader: () => Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => OpenAICredentialManifest | undefined;
  readonly onAlarm: (code: string) => void;
  readonly usageSink?: InferenceUsageSink;
  readonly createTransport?: () => OpenAITransport;
}

/** Builds the transport and key source only when the first embed takes the route, so a disabled route never reads the key. */
export class OpenAIEmbedRouteComposition {
  private backend: OpenAIEmbeddingsBackend | undefined;

  constructor(private readonly deps: OpenAIEmbedRouteCompositionDeps) {}

  provider(): EmbeddingProvider | undefined {
    const { state } = this.deps;
    if (state.kind === 'disabled') return undefined;
    if (state.kind === 'invalid') return this.refusing();
    return {
      cacheLabel: OPENAI_EMBED_CACHE_LABEL,
      embed: async (text) => this.backendFor(state).embed(text),
    };
  }

  private refusing(): EmbeddingProvider {
    return {
      cacheLabel: OPENAI_EMBED_CACHE_LABEL,
      embed: () => Promise.reject(new OpenAIEmbedRouteError('openai_embed_route_invalid')),
    };
  }

  private backendFor(
    state: Extract<OpenAIEmbedRouteState, { kind: 'enabled' }>,
  ): OpenAIEmbeddingsBackend {
    return (this.backend ??= this.build(state));
  }

  private transport(): OpenAITransport {
    try {
      return (this.deps.createTransport ?? createOpenAITransport)();
    } catch (error) {
      throw mapOpenAITransportError(error, { onAlarm: this.deps.onAlarm });
    }
  }

  private build(
    state: Extract<OpenAIEmbedRouteState, { kind: 'enabled' }>,
  ): OpenAIEmbeddingsBackend {
    const transport = this.transport();
    const credentials = new OpenAICredentialSource({
      reader: this.deps.reader(),
      manifest: this.deps.manifest,
      expected: state.identity,
      transport,
      onAlarm: this.deps.onAlarm,
    });
    return new OpenAIEmbeddingsBackend({
      fetch: transport.fetch,
      credentials,
      identity: state.identity,
      onAlarm: this.deps.onAlarm,
      ...(this.deps.usageSink === undefined ? {} : { usageSink: this.deps.usageSink }),
    });
  }
}
