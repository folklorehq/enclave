import {
  connectorOAuthMetadataUpdateSchema,
  type ConnectorOAuthMetadataUpdate,
} from '@folklore/contracts/enclave';
import type { CredentialSealer, OAuthStateGuard } from './EnclaveOAuthAuthorizationService.js';
import type { ProviderTokenClient } from './ProviderTokenClient.js';
import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';

export type GitHubInstallationSourceKind = 'github' | 'code';

export interface GitHubInstallationMetadata {
  orgId: string;
  deploymentId: string;
  accountId?: string;
  sourceKind: GitHubInstallationSourceKind;
  connectionId: string;
  installationId: string;
  stateBindingId: string;
  generation: string;
}

export interface GitHubInstallationCredentialPersistence {
  persistInstallationToken(input: {
    accountId?: string;
    encryptedAccessToken: string;
    metadata: ConnectorOAuthMetadataUpdate;
  }): Promise<void>;
}

export class EnclaveGitHubInstallationTokenService {
  constructor(
    private readonly sealer: CredentialSealer,
    private readonly persistence: GitHubInstallationCredentialPersistence,
    private readonly provider: ProviderTokenClient,
    private readonly configFor: (
      sourceKind: GitHubInstallationSourceKind,
    ) => VerifiedProviderConfig | null,
    private readonly states: OAuthStateGuard,
  ) {}

  async mint(input: GitHubInstallationMetadata): Promise<ConnectorOAuthMetadataUpdate> {
    const config = this.configFor(input.sourceKind);
    if (!config) throw new Error('github_provider_not_configured');
    if (
      !(await this.states.consume({
        orgId: input.orgId,
        deploymentId: input.deploymentId,
        sourceKind: input.sourceKind,
        stateBindingId: input.stateBindingId,
      }))
    ) {
      throw new Error('github_state_invalid');
    }
    let minted: { accessToken: string; expiresAt: string } | undefined;
    try {
      minted = await this.provider.mintGitHubInstallationToken({
        config,
        installationId: input.installationId,
      });
      if (
        !minted.accessToken ||
        minted.accessToken.length > 16_384 ||
        !minted.expiresAt ||
        !Number.isFinite(Date.parse(minted.expiresAt))
      ) {
        throw new Error('github_mint_failed');
      }
      const encryptedAccessToken = await this.sealer.seal({
        orgId: input.orgId,
        sourceKind: input.sourceKind,
        connectionId: input.connectionId,
        purpose: 'access',
        generation: input.generation,
        plaintext: Buffer.from(minted.accessToken, 'utf8'),
      });
      const { createHash } = await import('node:crypto');
      const metadata = connectorOAuthMetadataUpdateSchema.parse({
        orgId: input.orgId,
        deploymentId: input.deploymentId,
        connectionId: input.connectionId,
        sourceKind: input.sourceKind,
        attestationGeneration: input.generation,
        sourceUserId: null,
        externalTenantId: input.installationId,
        accessCiphertextSha256: createHash('sha256').update(encryptedAccessToken).digest('hex'),
        refreshCiphertextSha256: null,
        outcome: 'success',
      });
      await this.persistence.persistInstallationToken({
        accountId: input.accountId,
        encryptedAccessToken,
        metadata,
      });
      return metadata;
    } catch {
      throw new Error('github_mint_failed');
    } finally {
      if (minted) minted.accessToken = '';
    }
  }
}
