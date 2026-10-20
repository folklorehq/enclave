import type { AttestedSsmParameterReader } from '../../attestation/AttestedSsmParameterReader.js';
import {
  createAnthropicTransport,
  type AnthropicTransport,
} from '../../egress/anthropic-transport.js';
import type { OperationAuthority } from '../OperationAuthority.js';
import { ClaudeCredentialSource, type ClaudeCredentialManifest } from './ClaudeCredentialSource.js';
import type { InferenceRouteResolver } from '../routing/InferenceRouteResolver.js';
import type {
  ProviderRouteAdapter,
  ProviderRouteBackendFactory,
  ProviderSizeInput,
} from '../routing/ProviderRouteRegistry.js';
import { createClaudeOperationBackendFactory } from './ClaudeOperationBackendFactory.js';
import { isAnthropicRoute } from './anthropic-route.js';
import { fitsModel } from './claude-request.js';
import { CLAUDE_ROUTE_PROVIDER_MISMATCH, ClaudeRouteError } from './claude-route-errors.js';

export interface ClaudeRouteCompositionDeps {
  readonly resolver: InferenceRouteResolver;
  readonly reader: () => Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => ClaudeCredentialManifest | undefined;
  readonly createTransport?: (allowedModels: readonly string[]) => AnthropicTransport;
  readonly onAlarm?: (code: string) => void;
}

const defaultTransport = (allowedModels: readonly string[]): AnthropicTransport =>
  createAnthropicTransport({ allowedModels });

/** Builds the transport and key source only when a call first takes the Claude route, so a disabled route never reads the key. */
export class ClaudeRouteComposition implements ProviderRouteAdapter {
  readonly provider = 'anthropic' as const;
  private transport: AnthropicTransport | undefined;
  private credentials: ClaudeCredentialSource | undefined;

  constructor(private readonly deps: ClaudeRouteCompositionDeps) {}

  get enabled(): boolean {
    return this.deps.resolver.enabled;
  }

  fitsModel(input: ProviderSizeInput): boolean {
    const { route } = input;
    if (!isAnthropicRoute(route)) throw new ClaudeRouteError(CLAUDE_ROUTE_PROVIDER_MISMATCH);
    return fitsModel({ ...input, route });
  }

  backendFactory(authority: OperationAuthority): ProviderRouteBackendFactory {
    return createClaudeOperationBackendFactory({
      resolver: this.deps.resolver,
      authority,
      credentials: () => this.credentialSource(),
      transport: () => this.anthropicTransport(),
      ...this.alarm(),
    });
  }

  private anthropicTransport(): AnthropicTransport {
    const allowedModels = this.deps.resolver.allowedModels();
    return (this.transport ??= (this.deps.createTransport ?? defaultTransport)(allowedModels));
  }

  private credentialSource(): ClaudeCredentialSource {
    return (this.credentials ??= new ClaudeCredentialSource({
      reader: this.deps.reader(),
      manifest: this.deps.manifest,
      expected: this.deps.resolver.expectedIdentity(),
      allowedModels: this.deps.resolver.allowedModels(),
      transport: this.anthropicTransport(),
      ...this.alarm(),
    }));
  }

  private alarm(): { readonly onAlarm?: (code: string) => void } {
    const { onAlarm } = this.deps;
    return onAlarm === undefined ? {} : { onAlarm };
  }
}
