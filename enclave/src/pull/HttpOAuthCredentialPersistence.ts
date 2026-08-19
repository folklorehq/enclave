import {
  memberIdentityLinkPersistenceSchema,
  type MemberIdentityLinkPersistence,
} from '@folklore/contracts';
import {
  oauthRefreshMetadataUpdateSchema,
  sealedOAuthCredentialPersistenceSchema,
  webhookLifecycleClaimSchema,
  webhookLifecycleRenewSchema,
  webhookLifecycleCleanupClearSchema,
  webhookLifecycleDeliverySchema,
  webhookLifecycleFinalizeSchema,
  retiredOAuthCredentialLookupSchema,
  retiredOAuthCredentialSchema,
  type WebhookLifecycleClaim,
  type WebhookLifecycleRenew,
  type WebhookLifecycleCleanupClear,
  type WebhookLifecycleDelivery,
  type WebhookLifecycleFinalize,
  type RetiredOAuthCredential,
  type RetiredOAuthCredentialLookup,
} from '@folklore/contracts/enclave';
import { z, type ZodType } from 'zod';
import type { RefreshCredentialPersistence } from './EnclaveOAuthRefreshService.js';
import type { SealedCredentialPersistence } from './EnclaveOAuthAuthorizationService.js';
import type { GitHubInstallationCredentialPersistence } from './EnclaveGitHubInstallationTokenService.js';
import type { MemberIdentityLinkPersistencePort } from './EnclaveOAuthAuthorizationService.js';

export interface OAuthCredentialPersistenceTransport {
  post(path: string, body: unknown): Promise<{ status: number; body?: unknown }>;
}

export type CompareAndSwapResult =
  | 'updated'
  | 'stale'
  | 'attestation_unavailable'
  | 'persist_failed';

export interface WebhookLifecyclePersistence {
  claimWebhookLifecycle(
    input: WebhookLifecycleClaim,
  ): Promise<{ claimId: string; revision: number } | 'busy' | 'stale' | 'invalid_submission'>;
  renewWebhookLifecycleClaim(
    input: WebhookLifecycleRenew,
  ): Promise<'renewed' | 'stale' | 'invalid_submission' | 'attestation_unavailable'>;
  finalizeWebhookLifecycle(
    input: WebhookLifecycleFinalize,
  ): Promise<'updated' | 'stale' | 'invalid_submission'>;
  clearWebhookCleanupTombstone(
    input: WebhookLifecycleCleanupClear,
  ): Promise<'updated' | 'stale' | 'invalid_submission'>;
  recordWebhookDelivery(
    input: WebhookLifecycleDelivery,
  ): Promise<'updated' | 'stale' | 'invalid_submission'>;
}

export interface RetiredOAuthCredentialPersistence {
  getRetiredCredential(input: RetiredOAuthCredentialLookup): Promise<RetiredOAuthCredential | null>;
}

const refreshPersistenceSchema = z
  .object({
    expectedRefreshCiphertextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    nextAccessCiphertextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    nextRefreshCiphertextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    encryptedAccessToken: z.string().min(1).max(2_000_000),
    encryptedRefreshToken: z.string().min(1).max(2_000_000),
    metadata: oauthRefreshMetadataUpdateSchema,
  })
  .strict();

/** Sends only ESDK ciphertext and content-free routing metadata back to the control plane. */
export class HttpOAuthCredentialPersistence
  implements
    SealedCredentialPersistence,
    GitHubInstallationCredentialPersistence,
    RefreshCredentialPersistence,
    MemberIdentityLinkPersistencePort,
    WebhookLifecyclePersistence,
    RetiredOAuthCredentialPersistence
{
  constructor(private readonly transport: OAuthCredentialPersistenceTransport) {}

  async persistInitial(
    input: Parameters<SealedCredentialPersistence['persistInitial']>[0],
  ): Promise<void> {
    await this.post('/source-connection', {
      ...(input.accountId ? { accountId: input.accountId } : {}),
      encryptedAccessToken: input.encryptedAccessToken,
      ...(input.encryptedRefreshToken
        ? { encryptedRefreshToken: input.encryptedRefreshToken }
        : {}),
      metadata: input.metadata,
    });
  }

  async persistInstallationToken(
    input: Parameters<GitHubInstallationCredentialPersistence['persistInstallationToken']>[0],
  ): Promise<void> {
    await this.post('/source-connection', {
      ...(input.accountId ? { accountId: input.accountId } : {}),
      encryptedAccessToken: input.encryptedAccessToken,
      metadata: input.metadata,
    });
  }

  async compareAndSwap(
    input: Parameters<RefreshCredentialPersistence['compareAndSwap']>[0],
  ): Promise<CompareAndSwapResult> {
    const payload = {
      expectedRefreshCiphertextSha256: input.expectedRefreshCiphertextSha256,
      nextAccessCiphertextSha256: input.nextAccessCiphertextSha256,
      nextRefreshCiphertextSha256: input.nextRefreshCiphertextSha256,
      encryptedAccessToken: input.encryptedAccessToken,
      encryptedRefreshToken: input.encryptedRefreshToken,
      metadata: input.metadata,
    };
    let response: { status: number };
    try {
      response = await this.post(
        '/source-connection/refresh',
        payload,
        refreshPersistenceSchema,
        true,
      );
    } catch {
      response = await this.post(
        '/source-connection/refresh',
        payload,
        refreshPersistenceSchema,
        true,
      );
    }
    if (response.status === 202) return 'updated';
    if (response.status === 409) return 'stale';
    if (response.status === 412) return 'attestation_unavailable';
    return 'persist_failed';
  }

  async recordAudit(metadata: z.infer<typeof oauthRefreshMetadataUpdateSchema>): Promise<void> {
    await this.post('/source-connection/refresh-audit', metadata, oauthRefreshMetadataUpdateSchema);
  }

  async persist(input: MemberIdentityLinkPersistence): Promise<void> {
    await this.post('/member-identity-link', input, memberIdentityLinkPersistenceSchema);
  }

  async claimWebhookLifecycle(
    input: WebhookLifecycleClaim,
  ): Promise<{ claimId: string; revision: number } | 'busy' | 'stale' | 'invalid_submission'> {
    const response = await this.post(
      '/source-connection/webhook-lifecycle/claim',
      input,
      webhookLifecycleClaimSchema,
      true,
    );
    if (response.status === 200) {
      const parsed = z
        .object({ claimId: z.string().uuid(), revision: z.number().int().nonnegative() })
        .strict()
        .safeParse(response.body);
      return parsed.success ? parsed.data : 'invalid_submission';
    }
    return this.lifecycleError(response.status, response.body, true);
  }

  async renewWebhookLifecycleClaim(
    input: WebhookLifecycleRenew,
  ): Promise<'renewed' | 'stale' | 'invalid_submission' | 'attestation_unavailable'> {
    const response = await this.post(
      '/source-connection/webhook-lifecycle/renew',
      input,
      webhookLifecycleRenewSchema,
      true,
    );
    return response.status === 200
      ? 'renewed'
      : this.lifecycleError(response.status, response.body);
  }

  async finalizeWebhookLifecycle(
    input: WebhookLifecycleFinalize,
  ): Promise<'updated' | 'stale' | 'invalid_submission'> {
    const response = await this.post(
      '/source-connection/webhook-lifecycle/finalize',
      input,
      webhookLifecycleFinalizeSchema,
      true,
    );
    return response.status === 202
      ? 'updated'
      : this.lifecycleError(response.status, response.body);
  }

  async clearWebhookCleanupTombstone(
    input: WebhookLifecycleCleanupClear,
  ): Promise<'updated' | 'stale' | 'invalid_submission'> {
    const response = await this.post(
      '/source-connection/webhook-lifecycle/cleanup-clear',
      input,
      webhookLifecycleCleanupClearSchema,
      true,
    );
    return response.status === 202
      ? 'updated'
      : this.lifecycleError(response.status, response.body);
  }

  async recordWebhookDelivery(
    input: WebhookLifecycleDelivery,
  ): Promise<'updated' | 'stale' | 'invalid_submission'> {
    const response = await this.post(
      '/source-connection/webhook-lifecycle/delivery',
      input,
      webhookLifecycleDeliverySchema,
      true,
    );
    return response.status === 202
      ? 'updated'
      : this.lifecycleError(response.status, response.body);
  }

  async getRetiredCredential(
    input: RetiredOAuthCredentialLookup,
  ): Promise<RetiredOAuthCredential | null> {
    const response = await this.post(
      '/source-connection/retired-credential',
      input,
      retiredOAuthCredentialLookupSchema,
      true,
    );
    if (response.status !== 200) return null;
    const parsed = retiredOAuthCredentialSchema.safeParse(response.body);
    return parsed.success ? parsed.data : null;
  }

  private async post(
    path: string,
    body: unknown,
    schema: ZodType = sealedOAuthCredentialPersistenceSchema,
    allowNon2xx = false,
  ): Promise<{ status: number; body?: unknown }> {
    const parsed = schema.safeParse(body);
    if (!parsed.success) throw new Error('oauth_persistence_payload_invalid');
    const response = await this.transport.post(path, parsed.data);
    if (!allowNon2xx && (response.status < 200 || response.status >= 300)) {
      throw new Error('oauth_persistence_failed');
    }
    return response;
  }

  private lifecycleError(
    status: number,
    body: unknown,
    allowBusy: true,
  ): 'busy' | 'stale' | 'invalid_submission';
  private lifecycleError(
    status: number,
    body: unknown,
    allowBusy?: false,
  ): 'stale' | 'invalid_submission';
  private lifecycleError(
    status: number,
    body: unknown,
    allowBusy = false,
  ): 'busy' | 'stale' | 'invalid_submission' {
    if (status === 400) return 'invalid_submission';
    if (status !== 409) throw new Error('oauth_persistence_retryable');
    if (typeof body !== 'object' || body === null) return 'invalid_submission';
    const error = (body as { error?: unknown }).error;
    if (error === 'stale' || (allowBusy && error === 'busy')) return error;
    return 'invalid_submission';
  }
}
