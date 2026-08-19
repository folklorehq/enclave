import { sha256Hex } from '@folklore/utils';
import type { OAuthDisconnectCleanupCommand } from '@folklore/contracts/enclave';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { ProviderRejectedError } from '../egress/provider-token-fetch.js';
import type { JiraWebhookClientPort } from './HttpJiraWebhookClient.js';
import type { RetiredOAuthCredentialPersistence } from './HttpOAuthCredentialPersistence.js';

export interface JiraWebhookCleanupReceiptStore {
  hasCleanupReceipt(input: { orgId: string; cleanupKey: string }): Promise<boolean>;
  recordCleanupReceipt(input: { orgId: string; cleanupKey: string }): Promise<void>;
}

/** Deletes only the exact retired Jira registration while its sealed credential remains live. */
export class JiraWebhookDisconnectService {
  constructor(
    private readonly jira: JiraWebhookClientPort,
    private readonly persistence: RetiredOAuthCredentialPersistence,
    private readonly receipts?: JiraWebhookCleanupReceiptStore,
  ) {}

  async cleanup(input: OAuthDisconnectCleanupCommand, crypto: EnclaveCrypto): Promise<void> {
    if (input.kind !== 'jira') return;
    const credential = await this.persistence.getRetiredCredential({
      orgId: input.orgId,
      tenantDeploymentId: input.tenantDeploymentId,
      connectionId: input.connectionId,
      kind: input.kind,
      routeId: input.routeId,
      generation: input.generation,
      disconnectEraseAfter: input.disconnectEraseAfter,
    });
    if (!credential) throw new Error('jira_webhook_retired_credential_unavailable');
    if (credential.accessCiphertextSha256 !== sha256Hex(credential.encryptedAccessToken)) {
      throw new Error('jira_webhook_retired_credential_invalid');
    }
    if (
      credential.encryptedRefreshToken !== null &&
      credential.refreshCiphertextSha256 !== sha256Hex(credential.encryptedRefreshToken)
    ) {
      throw new Error('jira_webhook_retired_credential_invalid');
    }
    const externalTenantId = input.cleanupExternalTenantId;
    const registrationIds = input.cleanupRegistrationIds;
    if (!externalTenantId && !registrationIds) return;
    if (
      !externalTenantId ||
      !registrationIds ||
      credential.externalTenantId !== externalTenantId ||
      credential.cleanupExternalTenantId !== externalTenantId ||
      !this.sameRegistrationIds(credential.cleanupRegistrationIds, registrationIds) ||
      credential.cleanupExpiresAt !== input.cleanupExpiresAt
    ) {
      throw new Error('jira_webhook_cleanup_binding_invalid');
    }
    const cleanupKey = this.cleanupKey(input);
    if (
      this.receipts &&
      (await this.receipts.hasCleanupReceipt({ orgId: input.orgId, cleanupKey }))
    ) {
      return;
    }

    const ciphertext = Buffer.from(credential.encryptedAccessToken, 'base64');
    const accessTokenBytes = await this.decrypt(ciphertext, crypto, {
      orgId: input.orgId,
      sourceKind: input.kind,
      connectionId: input.connectionId,
      purpose: 'access',
      generation: input.generation,
    });
    const accessToken = accessTokenBytes.toString('utf8');
    try {
      try {
        await this.jira.delete({
          cloudId: externalTenantId,
          accessToken,
          registrationIds,
        });
      } catch (error) {
        if (!(error instanceof ProviderRejectedError) || error.status !== 404) throw error;
      }
      if (this.receipts) {
        await this.receipts.recordCleanupReceipt({ orgId: input.orgId, cleanupKey });
      }
    } finally {
      accessTokenBytes.fill(0);
      ciphertext.fill(0);
    }
  }

  private async decrypt(
    ciphertext: Buffer,
    crypto: EnclaveCrypto,
    ref: Parameters<EnclaveCrypto['decryptOAuthCredential']>[1],
  ): Promise<Buffer> {
    return crypto.decryptOAuthCredential(ciphertext, ref);
  }

  private sameRegistrationIds(left: readonly string[] | null, right: readonly string[]): boolean {
    return (
      left !== null &&
      left.length === right.length &&
      left.every((id, index) => id === right[index])
    );
  }

  private cleanupKey(input: OAuthDisconnectCleanupCommand): string {
    return sha256Hex(
      JSON.stringify([
        input.connectionId,
        input.routeId ?? null,
        input.generation,
        input.cleanupExternalTenantId ?? null,
        input.cleanupRegistrationIds ?? null,
        input.cleanupExpiresAt ?? null,
        input.disconnectEraseAfter,
      ]),
    );
  }
}
