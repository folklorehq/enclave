import { createHash } from 'node:crypto';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  oauthRefreshCommandSchema,
  oauthRefreshMetadataUpdateSchema,
  type OAuthRefreshMetadataUpdate,
  type OAuthRefreshCommand,
} from '@folklore/contracts/enclave';
import type { ProviderTokenClient, ProviderTokenResponse } from './ProviderTokenClient.js';
import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';
import { ProviderRejectedError } from '../egress/provider-token-fetch.js';
import type { CredentialSealer } from './EnclaveOAuthAuthorizationService.js';
import type { OAuthLeaseResolver } from './HttpOAuthLeaseResolver.js';
import type { CompareAndSwapResult } from './HttpOAuthCredentialPersistence.js';

export type RefreshCiphertextInput = OAuthRefreshCommand;

export interface RefreshCredentialPersistence {
  recordAudit?(metadata: OAuthRefreshMetadataUpdate): Promise<void>;
  compareAndSwap(input: {
    orgId: string;
    deploymentId: string;
    sourceKind: string;
    connectionId: string;
    generation: string;
    expectedRefreshCiphertextSha256: string;
    nextAccessCiphertextSha256: string;
    nextRefreshCiphertextSha256: string;
    encryptedAccessToken: string;
    encryptedRefreshToken: string;
    metadata: OAuthRefreshMetadataUpdate;
  }): Promise<CompareAndSwapResult>;
}

export class EnclaveOAuthRefreshService {
  constructor(
    private readonly crypto: EnclaveCrypto,
    private readonly sealer: CredentialSealer,
    private readonly persistence: RefreshCredentialPersistence,
    private readonly provider: ProviderTokenClient,
    private readonly configFor: (sourceKind: string) => VerifiedProviderConfig | null,
    private readonly leaseResolver: OAuthLeaseResolver,
  ) {}

  async redeem(input: RefreshCiphertextInput): Promise<OAuthRefreshMetadataUpdate> {
    const command = oauthRefreshCommandSchema.parse(input);
    const activeGeneration = await this.leaseResolver.resolve({
      orgId: command.orgId,
      deploymentId: command.deploymentId,
    });
    if (activeGeneration !== command.attestationGeneration) {
      return this.failure(command, 'attestation_unavailable');
    }
    if (this.hash(command.encryptedRefreshToken) !== command.expectedRefreshCiphertextSha256) {
      return this.failure(command, 'token_mismatch');
    }
    const config = this.configFor(command.sourceKind);
    if (!config || this.provider.refreshCapability(config) === 'unsupported') {
      return this.failure(command, 'unsupported_connector');
    }
    let refreshTokenBytes: Buffer | undefined;
    try {
      refreshTokenBytes = await this.decrypt(command);
    } catch {
      return this.failure(command, 'token_mismatch');
    }
    let response: ProviderTokenResponse | undefined;
    try {
      const refreshToken = refreshTokenBytes.toString('utf8');
      try {
        response = await this.provider.refreshAccessToken({ config, refreshToken });
      } catch (error) {
        return this.failure(
          command,
          error instanceof ProviderRejectedError ? 'provider_rejected' : 'provider_error',
        );
      }
      if (!response.accessToken) return this.failure(command, 'provider_rejected');
      if ((config.kind === 'linear' || config.kind === 'notion') && !response.refreshToken) {
        return this.failure(command, 'provider_rejected');
      }
      const nextRefreshToken = response.refreshToken ?? refreshToken;
      const accessTokenBytes = Buffer.from(response.accessToken, 'utf8');
      const nextRefreshTokenBytes = Buffer.from(nextRefreshToken, 'utf8');
      let encryptedAccessToken: string;
      let encryptedRefreshToken: string;
      try {
        encryptedAccessToken = await this.sealer.seal({
          orgId: command.orgId,
          sourceKind: command.sourceKind,
          connectionId: command.connectionId,
          purpose: 'access',
          generation: command.attestationGeneration,
          plaintext: accessTokenBytes,
        });
        encryptedRefreshToken = await this.sealer.seal({
          orgId: command.orgId,
          sourceKind: command.sourceKind,
          connectionId: command.connectionId,
          purpose: 'refresh',
          generation: command.attestationGeneration,
          plaintext: nextRefreshTokenBytes,
        });
      } finally {
        accessTokenBytes.fill(0);
        nextRefreshTokenBytes.fill(0);
      }
      const metadata = oauthRefreshMetadataUpdateSchema.parse({
        orgId: command.orgId,
        deploymentId: command.deploymentId,
        connectionId: command.connectionId,
        sourceKind: command.sourceKind,
        attestationGeneration: command.attestationGeneration,
        attemptId: command.attemptId,
        priorRefreshCiphertextSha256: command.expectedRefreshCiphertextSha256,
        nextAccessCiphertextSha256: this.hash(encryptedAccessToken),
        nextRefreshCiphertextSha256: this.hash(encryptedRefreshToken),
        outcome: 'success',
      });
      let persisted: CompareAndSwapResult;
      try {
        persisted = await this.persistence.compareAndSwap({
          ...command,
          generation: command.attestationGeneration,
          encryptedAccessToken,
          encryptedRefreshToken,
          expectedRefreshCiphertextSha256: command.expectedRefreshCiphertextSha256,
          nextAccessCiphertextSha256: metadata.nextAccessCiphertextSha256,
          nextRefreshCiphertextSha256: metadata.nextRefreshCiphertextSha256,
          metadata,
        });
      } catch {
        return this.failure(command, 'persist_failed');
      }
      if (persisted === 'stale') return this.failureWithoutAudit(command, 'stale_write');
      if (persisted === 'attestation_unavailable') {
        return this.failureWithoutAudit(command, 'attestation_unavailable');
      }
      if (persisted === 'persist_failed') {
        return this.failureWithoutAudit(command, 'persist_failed');
      }
      return metadata;
    } finally {
      refreshTokenBytes?.fill(0);
      if (response) {
        response.accessToken = '';
        if (response.refreshToken) response.refreshToken = '';
      }
    }
  }

  private async failure(
    command: RefreshCiphertextInput,
    outcome: OAuthRefreshMetadataUpdate['outcome'],
  ): Promise<OAuthRefreshMetadataUpdate> {
    const metadata = oauthRefreshMetadataUpdateSchema.parse({
      deploymentId: command.deploymentId,
      orgId: command.orgId,
      connectionId: command.connectionId,
      sourceKind: command.sourceKind,
      attestationGeneration: command.attestationGeneration,
      attemptId: command.attemptId,
      priorRefreshCiphertextSha256: command.expectedRefreshCiphertextSha256,
      nextAccessCiphertextSha256: command.expectedRefreshCiphertextSha256,
      nextRefreshCiphertextSha256: command.expectedRefreshCiphertextSha256,
      outcome,
    });
    try {
      await this.persistence.recordAudit?.(metadata);
    } catch {
      // Audit failure never turns a closed refresh outcome into a credential-bearing error.
    }
    return metadata;
  }

  private failureWithoutAudit(
    command: RefreshCiphertextInput,
    outcome: OAuthRefreshMetadataUpdate['outcome'],
  ): OAuthRefreshMetadataUpdate {
    return this.failureMetadata(command, outcome);
  }

  private failureMetadata(
    command: RefreshCiphertextInput,
    outcome: OAuthRefreshMetadataUpdate['outcome'],
  ): OAuthRefreshMetadataUpdate {
    return oauthRefreshMetadataUpdateSchema.parse({
      deploymentId: command.deploymentId,
      orgId: command.orgId,
      connectionId: command.connectionId,
      sourceKind: command.sourceKind,
      attestationGeneration: command.attestationGeneration,
      attemptId: command.attemptId,
      priorRefreshCiphertextSha256: command.expectedRefreshCiphertextSha256,
      nextAccessCiphertextSha256: command.expectedRefreshCiphertextSha256,
      nextRefreshCiphertextSha256: command.expectedRefreshCiphertextSha256,
      outcome,
    });
  }

  private async decrypt(input: RefreshCiphertextInput): Promise<Buffer> {
    try {
      return await this.crypto.decryptOAuthCredential(
        Buffer.from(input.encryptedRefreshToken, 'base64'),
        {
          orgId: input.orgId,
          sourceKind: input.sourceKind,
          connectionId: input.connectionId,
          purpose: 'refresh',
          generation: input.attestationGeneration,
        },
      );
    } catch {
      throw new Error('refresh_ciphertext_invalid');
    }
  }

  private hash(value: string | Buffer): string {
    return createHash('sha256').update(value).digest('hex');
  }
}
