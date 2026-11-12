import type { AttestedSsmParameterReader } from '../../attestation/AttestedSsmParameterReader.js';
import type { TenantBatchConsent } from '../../directory/TenantBatchConsent.js';
import {
  createAnthropicTransport,
  type AnthropicIdentity,
  type AnthropicTransport,
} from '../../egress/anthropic-transport.js';
import type { OperationAuthority } from '../OperationAuthority.js';
import {
  CLAUDE_BATCH_CREDENTIAL_LOCATION,
  ClaudeCredentialSource,
  type ClaudeCredentialManifest,
} from './ClaudeCredentialSource.js';
import { BatchApiClient } from './BatchApiClient.js';
import { BatchSendRoute } from './BatchingClaudeSender.js';
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
  readonly createTransport?: (
    allowedModels: readonly string[],
    identity: AnthropicIdentity,
  ) => AnthropicTransport;
  readonly onAlarm?: (code: string) => void;
  readonly batch?: { readonly consent: Pick<TenantBatchConsent, 'allows'> };
}

export interface BatchRouteHandle {
  readonly api: BatchApiClient;
  ready(): Promise<boolean>;
}

const BATCH_PREFLIGHT_FAILED = 'batch_preflight_failed';

const defaultTransport = (
  allowedModels: readonly string[],
  identity: AnthropicIdentity,
): AnthropicTransport => createAnthropicTransport({ allowedModels, identity });

/** Builds the transport and key source only when a call first takes the Claude route, so a disabled route never reads the key. */
export class ClaudeRouteComposition implements ProviderRouteAdapter {
  readonly provider = 'anthropic' as const;
  private transport: AnthropicTransport | undefined;
  private credentials: ClaudeCredentialSource | undefined;
  private batchTransport: AnthropicTransport | undefined;
  private batchCredentials: ClaudeCredentialSource | undefined;
  private batchHandle: BatchRouteHandle | undefined;

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
      ...this.batching(),
      ...this.alarm(),
    });
  }

  get batchActive(): boolean {
    return this.deps.batch !== undefined && this.deps.resolver.batchActive;
  }

  batchRoute(): BatchRouteHandle | undefined {
    if (!this.batchActive) return undefined;
    return (this.batchHandle ??= this.buildBatchHandle());
  }

  private batching(): { readonly batching?: BatchSendRoute } {
    const consent = this.deps.batch?.consent;
    if (consent === undefined) return {};
    return { batching: new BatchSendRoute({ enabled: () => this.batchActive, consent }) };
  }

  private buildBatchHandle(): BatchRouteHandle {
    const credentials = this.batchCredentialSource();
    const api = new BatchApiClient({
      fetch: (input, init) => this.batchTransportFor().fetch(input, init),
      apiKey: () => credentials.key(),
      expected: this.deps.resolver.batchIdentity(),
      onIdentityMismatch: () => credentials.invalidate('mismatch'),
      onCredentialRejected: () => credentials.invalidate('rejected'),
    });
    return { api, ready: () => this.preflightPasses(credentials) };
  }

  private async preflightPasses(credentials: ClaudeCredentialSource): Promise<boolean> {
    try {
      await credentials.key();
      return true;
    } catch {
      this.deps.onAlarm?.(BATCH_PREFLIGHT_FAILED);
      return false;
    }
  }

  private batchTransportFor(): AnthropicTransport {
    return (this.batchTransport ??= this.newTransport('batch'));
  }

  private batchCredentialSource(): ClaudeCredentialSource {
    return (this.batchCredentials ??= this.newCredentials('batch'));
  }

  private anthropicTransport(): AnthropicTransport {
    return (this.transport ??= this.newTransport('synchronous'));
  }

  private credentialSource(): ClaudeCredentialSource {
    return (this.credentials ??= this.newCredentials('synchronous'));
  }

  private newTransport(identity: AnthropicIdentity): AnthropicTransport {
    const allowedModels = this.deps.resolver.allowedModels();
    return (this.deps.createTransport ?? defaultTransport)(allowedModels, identity);
  }

  private newCredentials(identity: AnthropicIdentity): ClaudeCredentialSource {
    const batch = identity === 'batch';
    return new ClaudeCredentialSource({
      reader: this.deps.reader(),
      manifest: this.deps.manifest,
      expected: batch ? this.deps.resolver.batchIdentity() : this.deps.resolver.expectedIdentity(),
      allowedModels: this.deps.resolver.allowedModels(),
      transport: batch ? this.batchTransportFor() : this.anthropicTransport(),
      ...(batch ? { location: CLAUDE_BATCH_CREDENTIAL_LOCATION } : {}),
      ...this.alarm(),
    });
  }

  private alarm(): { readonly onAlarm?: (code: string) => void } {
    const { onAlarm } = this.deps;
    return onAlarm === undefined ? {} : { onAlarm };
  }
}
