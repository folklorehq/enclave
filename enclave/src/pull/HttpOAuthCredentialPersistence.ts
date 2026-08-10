import {
  memberIdentityLinkPersistenceSchema,
  type MemberIdentityLinkPersistence,
} from '@folklore/contracts';
import {
  oauthRefreshMetadataUpdateSchema,
  sealedOAuthCredentialPersistenceSchema,
} from '@folklore/contracts/enclave';
import { z, type ZodType } from 'zod';
import type { RefreshCredentialPersistence } from './EnclaveOAuthRefreshService.js';
import type { SealedCredentialPersistence } from './EnclaveOAuthAuthorizationService.js';
import type { GitHubInstallationCredentialPersistence } from './EnclaveGitHubInstallationTokenService.js';
import type { MemberIdentityLinkPersistencePort } from './EnclaveOAuthAuthorizationService.js';

export interface OAuthCredentialPersistenceTransport {
  post(path: string, body: unknown): Promise<{ status: number }>;
}

export type CompareAndSwapResult =
  | 'updated'
  | 'stale'
  | 'attestation_unavailable'
  | 'persist_failed';

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
    MemberIdentityLinkPersistencePort
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

  private async post(
    path: string,
    body: unknown,
    schema: ZodType = sealedOAuthCredentialPersistenceSchema,
    allowNon2xx = false,
  ): Promise<{ status: number }> {
    const parsed = schema.safeParse(body);
    if (!parsed.success) throw new Error('oauth_persistence_payload_invalid');
    const response = await this.transport.post(path, parsed.data);
    if (!allowNon2xx && (response.status < 200 || response.status >= 300)) {
      throw new Error('oauth_persistence_failed');
    }
    return response;
  }
}
