import type { RoutedProviderId } from '@folklore/contracts';
import {
  ProviderRouteError,
  type VerifiedActivePolicyRoleBindingV1,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import type { CachedSystemPrefix } from '../InferencePurposeScope.js';
import type { OperationAuthority } from '../OperationAuthority.js';
import type { TenantPolicyOperationBackend } from '../TenantPolicyBoundInference.js';
import type { ProviderRoute } from './InferenceRouteResolver.js';

export const INFERENCE_PROVIDER_UNREGISTERED = 'inference_provider_unregistered';
export const INFERENCE_PROVIDER_DUPLICATE = 'inference_provider_duplicate';

export type ProviderRouteBackendFactory = (
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
  route: ProviderRoute,
) => Promise<TenantPolicyOperationBackend>;

export interface ProviderSizeInput {
  readonly route: ProviderRoute;
  readonly prompt: string;
  readonly systemPrompt?: string;
  readonly cachedSystemPrefix?: CachedSystemPrefix;
}

export interface ProviderRouteAdapter {
  readonly provider: RoutedProviderId;
  readonly enabled: boolean;
  backendFactory(authority: OperationAuthority): ProviderRouteBackendFactory;
  fitsModel(input: ProviderSizeInput): boolean;
}

export class ProviderRouteRegistry {
  private readonly byProvider = new Map<RoutedProviderId, ProviderRouteAdapter>();

  constructor(adapters: readonly ProviderRouteAdapter[]) {
    for (const adapter of adapters) {
      if (this.byProvider.has(adapter.provider)) {
        throw new ProviderRouteError({
          provider: adapter.provider,
          code: INFERENCE_PROVIDER_DUPLICATE,
        });
      }
      this.byProvider.set(adapter.provider, adapter);
    }
  }

  adapterFor(provider: RoutedProviderId): ProviderRouteAdapter {
    const adapter = this.byProvider.get(provider);
    if (adapter === undefined) {
      throw new ProviderRouteError({ provider, code: INFERENCE_PROVIDER_UNREGISTERED });
    }
    return adapter;
  }

  providers(): readonly RoutedProviderId[] {
    return [...this.byProvider.keys()];
  }
}
