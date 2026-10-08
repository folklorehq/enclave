import { createHash } from 'node:crypto';
import {
  connectorOAuthMetadataUpdateSchema,
  type ConnectorOAuthMetadataUpdate,
  type EnclaveAuthorizationCodeGrant,
} from '@folklore/contracts/enclave';
import type { CredentialSealer, OAuthStateGuard } from './EnclaveOAuthAuthorizationService.js';
import type { ProviderTokenClient } from './ProviderTokenClient.js';
import type { SealedCodeGrantOpener } from './SealedCodeGrantOpener.js';
import { gitHubInstallationBindingPlaintext } from './github-installation-binding.js';
import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';

const OWNERSHIP_UNVERIFIED = 'github_installation_ownership_unverified';

export type GitHubInstallationSourceKind = 'github';

export interface GitHubInstallationMetadata {
  orgId: string;
  deploymentId: string;
  accountId?: string;
  sourceKind: GitHubInstallationSourceKind;
  connectionId: string;
  installationId: string;
  stateBindingId: string;
  generation: string;
  activationGeneration: string;
  encryptedCodeGrant: string;
  ciphertextSha256: string;
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
    private readonly grants: SealedCodeGrantOpener,
  ) {}

  async mint(input: GitHubInstallationMetadata): Promise<ConnectorOAuthMetadataUpdate> {
    const config = this.configFor(input.sourceKind);
    if (!config) throw new Error('github_provider_not_configured');
    const grant = this.openInstallCode(input);
    try {
      await this.consumeState(input);
      await this.requireInstallationOwnership(config, grant, input.installationId);
    } finally {
      grant.authorizationCode = '';
    }
    return this.mintAndPersist(config, input);
  }

  private openInstallCode(input: GitHubInstallationMetadata): EnclaveAuthorizationCodeGrant {
    if (!input.encryptedCodeGrant) throw new Error(OWNERSHIP_UNVERIFIED);
    let grant: EnclaveAuthorizationCodeGrant;
    try {
      grant = this.grants.open(input);
    } catch {
      throw new Error(OWNERSHIP_UNVERIFIED);
    }
    if (!this.grantMatches(grant, input)) {
      grant.authorizationCode = '';
      throw new Error(OWNERSHIP_UNVERIFIED);
    }
    return grant;
  }

  private grantMatches(grant: EnclaveAuthorizationCodeGrant, input: GitHubInstallationMetadata) {
    return (
      grant.sourceKind === input.sourceKind &&
      grant.orgId === input.orgId &&
      grant.deploymentId === input.deploymentId &&
      grant.connectionId === input.connectionId &&
      grant.activationGeneration === input.activationGeneration &&
      grant.attestationGeneration === input.generation &&
      grant.stateBindingId === input.stateBindingId &&
      grant.accountId === input.accountId &&
      grant.installationId === input.installationId &&
      Date.parse(grant.expiresAt) > Date.now()
    );
  }

  private async consumeState(input: GitHubInstallationMetadata): Promise<void> {
    const consumed = await this.states.consume({
      orgId: input.orgId,
      deploymentId: input.deploymentId,
      sourceKind: input.sourceKind,
      stateBindingId: input.stateBindingId,
    });
    if (!consumed) throw new Error('github_state_invalid');
  }

  // The App JWT mints for any installation, so the installing user must own this one's account.
  private async requireInstallationOwnership(
    config: VerifiedProviderConfig,
    grant: EnclaveAuthorizationCodeGrant,
    installationId: string,
  ): Promise<void> {
    let owned = false;
    try {
      owned = await this.provider.userAdministersGitHubInstallation({
        config,
        code: grant.authorizationCode,
        installationId,
      });
    } catch {
      owned = false;
    }
    if (!owned) throw new Error(OWNERSHIP_UNVERIFIED);
  }

  private async mintAndPersist(
    config: VerifiedProviderConfig,
    input: GitHubInstallationMetadata,
  ): Promise<ConnectorOAuthMetadataUpdate> {
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
      minted.accessToken = '';
      // Pulls mint per use, so the stored credential carries the proven installation, not a token.
      const encryptedAccessToken = await this.sealer.seal({
        orgId: input.orgId,
        sourceKind: input.sourceKind,
        connectionId: input.connectionId,
        purpose: 'access',
        generation: input.generation,
        plaintext: gitHubInstallationBindingPlaintext(input.installationId),
      });
      const metadata = connectorOAuthMetadataUpdateSchema.parse({
        orgId: input.orgId,
        deploymentId: input.deploymentId,
        connectionId: input.connectionId,
        sourceKind: input.sourceKind,
        activationGeneration: input.activationGeneration,
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
