import { eciesDecrypt } from '@folklore/crypto';
import {
  enclaveAuthorizationCodeGrantSchema,
  connectorOAuthMetadataUpdateSchema,
  type ConnectorOAuthMetadataUpdate,
  type SealedAuthorizationCodeSubmission,
} from '@folklore/contracts/enclave';
import {
  memberIdentityLinkPersistenceSchema,
  type MemberIdentityLinkPersistence as MemberIdentityLinkPersistenceRecord,
} from '@folklore/contracts';
import { createHash, type KeyObject } from 'node:crypto';
import type { ProviderTokenClient, ProviderTokenResponse } from './ProviderTokenClient.js';
import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';

interface AuthorizationGrant {
  version: 1;
  authorizationCode: string;
  codeVerifier: string | null;
  sourceKind: string;
  orgId: string;
  deploymentId: string;
  connectionId?: string;
  callbackUri: string;
  attestationGeneration: string;
  activationGeneration?: string;
  stateBindingId: string;
  issuedAt: string;
  expiresAt: string;
  accountId?: string;
  memberEmail?: string;
}

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
  constructor(
    private readonly privateKey: KeyObject,
    private readonly states: OAuthStateGuard,
    private readonly sealer: CredentialSealer,
    private readonly persistence: SealedCredentialPersistence,
    private readonly provider: ProviderTokenClient,
    private readonly configFor: (sourceKind: string) => VerifiedProviderConfig | null,
    private readonly memberIdentityPersistence?: MemberIdentityLinkPersistencePort,
  ) {}

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
      if (this.hash(submission.encryptedCodeGrant) !== submission.ciphertextSha256) {
        throw new Error('ciphertext_hash_mismatch');
      }
      const envelope = JSON.parse(submission.encryptedCodeGrant) as Parameters<
        typeof eciesDecrypt
      >[0];
      const firstPlaintext = eciesDecrypt(envelope, this.privateKey);
      const parsed: unknown = JSON.parse(firstPlaintext.toString('utf8'));
      firstPlaintext.fill(0);
      const grant = enclaveAuthorizationCodeGrantSchema.parse(parsed);
      const aad = this.grantAad(grant);
      const plaintext = eciesDecrypt(envelope, this.privateKey, aad);
      const checked: unknown = JSON.parse(plaintext.toString('utf8'));
      plaintext.fill(0);
      if (
        JSON.stringify(enclaveAuthorizationCodeGrantSchema.parse(checked)) !== JSON.stringify(grant)
      ) {
        throw new Error('grant_changed');
      }
      return grant;
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

  private grantAad(grant: AuthorizationGrant): string {
    return [
      'folklore.oauth-code-grant.v1',
      grant.deploymentId,
      grant.orgId,
      grant.sourceKind,
      grant.callbackUri,
      grant.attestationGeneration,
      grant.activationGeneration ?? '',
      grant.stateBindingId,
      grant.issuedAt,
      grant.expiresAt,
    ].join('|');
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
