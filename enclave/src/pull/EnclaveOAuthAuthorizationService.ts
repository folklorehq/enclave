import {
  connectorOAuthMetadataUpdateSchema,
  type ConnectorOAuthMetadataUpdate,
  type EnclaveAuthorizationCodeGrant,
  type SealedAuthorizationCodeSubmission,
} from '@folklore/contracts/enclave';
import {
  memberIdentityLinkPersistenceSchema,
  type MemberIdentityLinkPersistence as MemberIdentityLinkPersistenceRecord,
} from '@folklore/contracts';
import { createHash, type KeyObject } from 'node:crypto';
import type { ProviderTokenClient, ProviderTokenResponse } from './ProviderTokenClient.js';
import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';
import { SealedCodeGrantOpener } from './SealedCodeGrantOpener.js';

type AuthorizationGrant = EnclaveAuthorizationCodeGrant;

export interface OAuthStateGuard {
  consume(input: {
    orgId: string;
    deploymentId: string;
    sourceKind: string;
    stateBindingId: string;
  }): Promise<boolean>;
  consumeMember(input: {
    orgId: string;
    deploymentId: string;
    sourceKind: string;
    stateBindingId: string;
  }): Promise<boolean>;
}

export interface CredentialSealer {
  seal(input: {
    orgId: string;
    sourceKind: string;
    connectionId: string;
    purpose: 'access' | 'refresh';
    generation: string;
    plaintext: Buffer;
  }): Promise<string>;
}

export interface SealedCredentialPersistence {
  persistInitial(input: {
    accountId?: string;
    orgId: string;
    deploymentId: string;
    sourceKind: string;
    connectionId: string;
    generation: string;
    encryptedAccessToken: string;
    encryptedRefreshToken?: string;
    metadata: ConnectorOAuthMetadataUpdate;
  }): Promise<void>;
}

export interface MemberIdentityLinkPersistencePort {
  persist(input: MemberIdentityLinkPersistenceRecord): Promise<void>;
}

export class EnclaveOAuthRedemptionError extends Error {
  constructor() {
    super('oauth_redemption_failed');
    this.name = 'EnclaveOAuthRedemptionError';
  }
}

export class EnclaveOAuthAuthorizationService {
  private readonly grants: SealedCodeGrantOpener;

  constructor(
    privateKey: KeyObject,
    private readonly states: OAuthStateGuard,
    private readonly sealer: CredentialSealer,
    private readonly persistence: SealedCredentialPersistence,
    private readonly provider: ProviderTokenClient,
    private readonly configFor: (sourceKind: string) => VerifiedProviderConfig | null,
    private readonly memberIdentityPersistence?: MemberIdentityLinkPersistencePort,
  ) {
    this.grants = new SealedCodeGrantOpener(privateKey);
  }

  async redeem(
    submission: SealedAuthorizationCodeSubmission,
    generation: string,
  ): Promise<ConnectorOAuthMetadataUpdate> {
    if (submission.attestationGeneration !== generation) throw new EnclaveOAuthRedemptionError();
    const grant = this.decryptGrant(submission);
    if (!this.matches(submission, grant, generation)) throw new EnclaveOAuthRedemptionError();
    if (Date.parse(grant.expiresAt) <= Date.now()) throw new EnclaveOAuthRedemptionError();
    if (
      !(await this.states.consume({
        orgId: grant.orgId,
        deploymentId: grant.deploymentId,
        sourceKind: grant.sourceKind,
        stateBindingId: grant.stateBindingId,
      }))
    )
      throw new EnclaveOAuthRedemptionError();
    const config = this.configFor(grant.sourceKind);
    if (!config) throw new EnclaveOAuthRedemptionError();

    let response: ProviderTokenResponse | undefined;
    try {
      response = await this.provider.exchangeAuthorizationCode({
        config,
        code: grant.authorizationCode,
        ...(grant.codeVerifier ? { pkceVerifier: grant.codeVerifier } : {}),
        callbackUri: grant.callbackUri,
      });
      this.validateResponse(response);
      const identity = await this.provider.resolveIdentity({
        config,
        accessToken: response.accessToken,
      });
      response.sourceUserId = identity.sourceUserId;
      response.externalTenantId = identity.externalTenantId ?? response.externalTenantId;
      const connectionId = this.requireConnectionId(grant);
      const activationGeneration = this.requireActivationGeneration(grant);
      const encryptedAccessToken = await this.sealer.seal({
        orgId: grant.orgId,
        sourceKind: grant.sourceKind,
        connectionId,
        purpose: 'access',
        generation: grant.attestationGeneration,
        plaintext: Buffer.from(response.accessToken, 'utf8'),
      });
      const encryptedRefreshToken = response.refreshToken
        ? await this.sealer.seal({
            orgId: grant.orgId,
            sourceKind: grant.sourceKind,
            connectionId,
            purpose: 'refresh',
            generation: grant.attestationGeneration,
            plaintext: Buffer.from(response.refreshToken, 'utf8'),
          })
        : undefined;
      const metadata = connectorOAuthMetadataUpdateSchema.parse({
        orgId: grant.orgId,
        deploymentId: grant.deploymentId,
        connectionId,
        activationGeneration,
        sourceKind: grant.sourceKind,
        attestationGeneration: grant.attestationGeneration,
        sourceUserId: response.sourceUserId ?? null,
        externalTenantId: response.externalTenantId ?? null,
        accessCiphertextSha256: this.hash(encryptedAccessToken),
        refreshCiphertextSha256: encryptedRefreshToken ? this.hash(encryptedRefreshToken) : null,
        outcome: 'success',
      });
      await this.persistence.persistInitial({
        orgId: grant.orgId,
        deploymentId: grant.deploymentId,
        sourceKind: grant.sourceKind,
        connectionId,
        accountId: grant.accountId,
        generation: grant.attestationGeneration,
        encryptedAccessToken,
        ...(encryptedRefreshToken ? { encryptedRefreshToken } : {}),
        metadata,
      });
      return metadata;
    } catch (error) {
      if (error instanceof EnclaveOAuthRedemptionError) throw error;
      throw new EnclaveOAuthRedemptionError();
    } finally {
      grant.authorizationCode = '';
      grant.codeVerifier = null;
      if (response) {
        response.accessToken = '';
        if (response.refreshToken) response.refreshToken = '';
      }
    }
  }

  async redeemMemberIdentity(
    submission: SealedAuthorizationCodeSubmission,
    generation: string,
  ): Promise<MemberIdentityLinkPersistenceRecord> {
    if (submission.attestationGeneration !== generation) throw new EnclaveOAuthRedemptionError();
    const grant = this.decryptGrant(submission);
    let response: ProviderTokenResponse | undefined;
    try {
      if (!this.matches(submission, grant, generation)) throw new EnclaveOAuthRedemptionError();
      if (Date.parse(grant.expiresAt) <= Date.now()) throw new EnclaveOAuthRedemptionError();
      if (!grant.accountId || !grant.memberEmail) throw new EnclaveOAuthRedemptionError();
      if (
        !(await this.states.consumeMember({
          orgId: grant.orgId,
          deploymentId: grant.deploymentId,
          sourceKind: grant.sourceKind,
          stateBindingId: grant.stateBindingId,
        }))
      ) {
        throw new EnclaveOAuthRedemptionError();
      }
      const config = this.configFor(grant.sourceKind);
      if (!config) throw new EnclaveOAuthRedemptionError();
      response = await this.provider.exchangeAuthorizationCode({
        config,
        code: grant.authorizationCode,
        ...(grant.codeVerifier ? { pkceVerifier: grant.codeVerifier } : {}),
        callbackUri: grant.callbackUri,
      });
      this.validateResponse(response);
      const identity = await this.provider.resolveIdentity({
        config,
        accessToken: response.accessToken,
      });
      const link = memberIdentityLinkPersistenceSchema.parse({
        deploymentId: grant.deploymentId,
        orgId: grant.orgId,
        attestationGeneration: generation,
        accountId: grant.accountId,
        sourceKind: grant.sourceKind,
        memberEmail: grant.memberEmail,
        sourceUserId: identity.sourceUserId,
      });
      if (!this.memberIdentityPersistence) throw new EnclaveOAuthRedemptionError();
      await this.memberIdentityPersistence.persist(link);
      return link;
    } catch (error) {
      if (error instanceof EnclaveOAuthRedemptionError) throw error;
      throw new EnclaveOAuthRedemptionError();
    } finally {
      grant.authorizationCode = '';
      grant.codeVerifier = null;
      if (response) {
        response.accessToken = '';
        if (response.refreshToken) response.refreshToken = '';
      }
    }
  }

  private decryptGrant(submission: SealedAuthorizationCodeSubmission): AuthorizationGrant {
    try {
      return this.grants.open(submission);
    } catch {
      throw new EnclaveOAuthRedemptionError();
    }
  }

  private matches(
    submission: SealedAuthorizationCodeSubmission,
    grant: AuthorizationGrant,
    generation: string,
  ): boolean {
    return (
      grant.orgId === submission.orgId &&
      grant.deploymentId === submission.deploymentId &&
      grant.sourceKind === submission.sourceKind &&
      grant.attestationGeneration === generation &&
      grant.attestationGeneration === submission.attestationGeneration &&
      grant.stateBindingId === submission.stateBindingId
    );
  }

  private requireConnectionId(grant: AuthorizationGrant): string {
    if (!grant.connectionId) throw new EnclaveOAuthRedemptionError();
    return grant.connectionId;
  }

  private requireActivationGeneration(grant: AuthorizationGrant): string {
    if (!grant.activationGeneration) throw new EnclaveOAuthRedemptionError();
    return grant.activationGeneration;
  }

  private validateResponse(response: ProviderTokenResponse): void {
    if (!response.accessToken || response.accessToken.length > 16_384) {
      throw new EnclaveOAuthRedemptionError();
    }
    if (response.refreshToken !== undefined && response.refreshToken.length > 16_384) {
      throw new EnclaveOAuthRedemptionError();
    }
    if (response.expiresInSeconds !== undefined && response.expiresInSeconds <= 0) {
      throw new EnclaveOAuthRedemptionError();
    }
  }

  private hash(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }
}
