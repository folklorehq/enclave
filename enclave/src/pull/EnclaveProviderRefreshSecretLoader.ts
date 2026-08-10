import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';
import { decryptRecipientCiphertext } from '../sealing/seal.js';

export interface ProviderSecretMaterial {
  clientId: string;
  clientSecret: string;
  githubAppPrivateKey?: string;
}

export interface ProviderRefreshSecretLoader {
  load(config: VerifiedProviderConfig): Promise<ProviderSecretMaterial>;
}

export class EnclaveProviderRefreshSecretLoader implements ProviderRefreshSecretLoader {
  constructor(
    private readonly secrets: {
      getSecretValue(input: { secretId: string }): Promise<Uint8Array>;
    },
    private readonly kmsKeyId: string,
  ) {}

  async load(config: VerifiedProviderConfig): Promise<ProviderSecretMaterial> {
    const ciphertext = Buffer.from(
      await this.secrets.getSecretValue({ secretId: config.oauthSecretRef }),
    );
    const plaintext = await decryptRecipientCiphertext(ciphertext, this.kmsKeyId, {
      purpose: 'provider-oauth-secret',
      version: '1',
      secretRef: config.oauthSecretRef,
    });
    try {
      const parsed: unknown = JSON.parse(plaintext.toString('utf8'));
      if (!parsed || typeof parsed !== 'object') throw new Error('invalid_provider_secret');
      const record = parsed as Record<string, unknown>;
      const clientId = record['clientId'];
      const clientSecret = record['clientSecret'];
      const githubAppPrivateKey = record['githubAppPrivateKey'];
      if (typeof clientId !== 'string' || clientId.length === 0) {
        throw new Error('invalid_provider_secret');
      }
      if (typeof clientSecret !== 'string' || clientSecret.length === 0) {
        throw new Error('invalid_provider_secret');
      }
      if (githubAppPrivateKey !== undefined && typeof githubAppPrivateKey !== 'string') {
        throw new Error('invalid_provider_secret');
      }
      const privateKey = typeof githubAppPrivateKey === 'string' ? githubAppPrivateKey : undefined;
      return { clientId, clientSecret, ...(privateKey ? { githubAppPrivateKey: privateKey } : {}) };
    } finally {
      plaintext.fill(0);
      ciphertext.fill(0);
    }
  }
}
