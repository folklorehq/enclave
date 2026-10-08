import type {
  ProviderRefreshCapability,
  VerifiedProviderConfig,
} from '../egress/provider-token-fetch.js';

export interface ProviderTokenResponse {
  accessToken: string;
  refreshToken?: string;
  expiresInSeconds?: number;
  sourceUserId?: string;
  externalTenantId?: string;
}

export interface ProviderTokenClient {
  refreshCapability(config: VerifiedProviderConfig): ProviderRefreshCapability;
  exchangeAuthorizationCode(input: {
    config: VerifiedProviderConfig;
    code: string;
    pkceVerifier?: string;
    callbackUri: string;
  }): Promise<ProviderTokenResponse>;
  refreshAccessToken(input: {
    config: VerifiedProviderConfig;
    refreshToken: string;
  }): Promise<ProviderTokenResponse>;
  resolveIdentity(input: {
    config: VerifiedProviderConfig;
    accessToken: string;
  }): Promise<{ sourceUserId: string; externalTenantId?: string }>;
  mintGitHubInstallationToken(input: {
    config: VerifiedProviderConfig;
    installationId: string;
  }): Promise<{ accessToken: string; expiresAt: string }>;
  /** True only when the user behind the install-time code owns the installation's account. */
  userAdministersGitHubInstallation(input: {
    config: VerifiedProviderConfig;
    code: string;
    installationId: string;
  }): Promise<boolean>;
}
