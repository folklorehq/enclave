import { createSign } from 'node:crypto';
import type { ProviderTokenClient, ProviderTokenResponse } from './ProviderTokenClient.js';
import type { ProviderRefreshSecretLoader } from './EnclaveProviderRefreshSecretLoader.js';
import {
  assertSupportedProvider,
  createProviderTokenFetch,
  refreshCapability as providerRefreshCapability,
  type ProviderRefreshCapability,
  type ProviderTokenRequest,
  type ProviderTokenFetchOptions,
  type VerifiedProviderConfig,
} from '../egress/provider-token-fetch.js';

const TOKEN_MAX_BYTES = 512 * 1024;
const TOKEN_VALUE_MAX_BYTES = 16 * 1024;
const ID_MAX_BYTES = 256;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Provider token exchange confined to the enclave's signed endpoint + proxy contract. */
export class HttpProviderTokenClient implements ProviderTokenClient {
  constructor(
    private readonly secrets: ProviderRefreshSecretLoader,
    private readonly options: ProviderTokenFetchOptions,
  ) {}

  refreshCapability(config: VerifiedProviderConfig): ProviderRefreshCapability {
    return providerRefreshCapability(config);
  }

  async exchangeAuthorizationCode(input: {
    config: VerifiedProviderConfig;
    code: string;
    pkceVerifier?: string;
    callbackUri: string;
  }): Promise<ProviderTokenResponse> {
    assertSupportedProvider(input.config.kind);
    const secret = await this.secrets.load(input.config);
    const response = await this.execute(input.config, {
      operation: 'code',
      clientId: secret.clientId,
      clientSecret: secret.clientSecret,
      code: input.code,
      callbackUri: input.callbackUri,
      ...(input.pkceVerifier ? { pkceVerifier: input.pkceVerifier } : {}),
    });
    return this.parseTokenResponse(input.config, 'code', response);
  }

  async refreshAccessToken(input: {
    config: VerifiedProviderConfig;
    refreshToken: string;
  }): Promise<ProviderTokenResponse> {
    assertSupportedProvider(input.config.kind);
    if (this.refreshCapability(input.config) === 'unsupported') {
      throw new Error('unsupported_connector');
    }
    const secret = await this.secrets.load(input.config);
    const response = await this.execute(input.config, {
      operation: 'refresh',
      clientId: secret.clientId,
      clientSecret: secret.clientSecret,
      refreshToken: input.refreshToken,
    });
    return this.parseTokenResponse(input.config, 'refresh', response);
  }

  async resolveIdentity(input: {
    config: VerifiedProviderConfig;
    accessToken: string;
  }): Promise<{ sourceUserId: string; externalTenantId?: string }> {
    assertSupportedProvider(input.config.kind);
    const response = await this.execute(input.config, {
      operation: 'identity',
      accessToken: input.accessToken,
    });
    const parsed = await this.parse(response);
    if (!isRecord(parsed)) throw new Error('provider_identity_response_invalid');
    if (input.config.kind === 'jira') {
      return {
        sourceUserId: this.requireId(parsed['account_id']),
        externalTenantId: await this.resolveJiraCloudId(input.config, input.accessToken),
      };
    }
    return this.identityFrom(input.config, parsed);
  }

  async mintGitHubInstallationToken(input: {
    config: VerifiedProviderConfig;
    installationId: string;
  }): Promise<{ accessToken: string; expiresAt: string }> {
    assertSupportedProvider(input.config.kind);
    if (input.config.kind !== 'github') throw new Error('github_provider_not_configured');
    const secret = await this.secrets.load(input.config);
    if (!secret.githubAppPrivateKey) throw new Error('github_app_key_unavailable');
    const response = await this.execute(input.config, {
      operation: 'github_installation',
      installationId: input.installationId,
      installationJwt: this.githubAppJwt(secret.clientId, secret.githubAppPrivateKey),
    });
    const parsed = await this.parse(response);
    if (!isRecord(parsed)) {
      throw new Error('github_token_response_invalid');
    }
    const accessToken = this.requireToken(parsed['token']);
    const expiresAt = typeof parsed['expires_at'] === 'string' ? parsed['expires_at'] : '';
    if (!expiresAt || !Number.isFinite(Date.parse(expiresAt))) {
      throw new Error('github_token_expiry_invalid');
    }
    return { accessToken, expiresAt };
  }

  private execute(
    config: VerifiedProviderConfig,
    request: ProviderTokenRequest,
  ): Promise<Response> {
    return createProviderTokenFetch(config, request, this.options)();
  }

  private async parseTokenResponse(
    config: VerifiedProviderConfig,
    operation: 'code' | 'refresh',
    response: Response,
  ): Promise<ProviderTokenResponse> {
    const parsed = await this.parse(response);
    if (!isRecord(parsed)) {
      throw new Error('provider_token_response_invalid');
    }
    const accessToken = this.requireToken(parsed['access_token']);
    const refreshToken =
      typeof parsed['refresh_token'] === 'string'
        ? this.requireToken(parsed['refresh_token'])
        : undefined;
    if (config.kind === 'linear' || config.kind === 'notion') {
      if (!refreshToken) throw new Error('provider_token_response_invalid');
    }
    const expiresIn = parsed['expires_in'];
    const result: ProviderTokenResponse = {
      accessToken,
      ...(typeof refreshToken === 'string' ? { refreshToken } : {}),
      ...(typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0
        ? { expiresInSeconds: expiresIn }
        : {}),
    };
    if (config.kind === 'notion' && operation === 'code') {
      result.sourceUserId = this.requireId(parsed['bot_id']);
      result.externalTenantId = this.requireId(parsed['workspace_id']);
    }
    return result;
  }

  private identityFrom(
    config: VerifiedProviderConfig,
    parsed: Record<string, unknown>,
  ): { sourceUserId: string; externalTenantId?: string } {
    if (config.kind === 'linear') return this.linearIdentity(parsed);
    if (config.kind === 'notion') return { sourceUserId: this.requireId(parsed['id']) };
    if (
      config.kind === 'google_drive' ||
      config.kind === 'gmail' ||
      config.kind === 'google_calendar'
    ) {
      return { sourceUserId: this.requireId(parsed['sub']) };
    }
    if (config.kind === 'intercom') {
      const app = parsed['app'];
      if (!isRecord(app)) throw new Error('provider_identity_missing');
      return {
        sourceUserId: this.requireId(parsed['id']),
        externalTenantId: this.requireId(app['id_code']),
      };
    }
    const sourceUserId = this.requireId(config.kind === 'slack' ? parsed['user_id'] : parsed['id']);
    const tenant = config.kind === 'slack' ? parsed['team_id'] : undefined;
    return {
      sourceUserId,
      ...(tenant !== undefined ? { externalTenantId: this.requireId(tenant) } : {}),
    };
  }

  private async resolveJiraCloudId(
    config: VerifiedProviderConfig,
    accessToken: string,
  ): Promise<string> {
    const response = await this.execute(config, { operation: 'jira_resources', accessToken });
    const parsed = await this.parse(response);
    if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
      throw new Error('provider_identity_missing');
    }
    const id = parsed[0]['id'];
    if (typeof id !== 'string' || !UUID_PATTERN.test(id)) {
      throw new Error('provider_identity_missing');
    }
    return id.toLowerCase();
  }

  private linearIdentity(parsed: Record<string, unknown>): {
    sourceUserId: string;
    externalTenantId: string;
  } {
    if (Array.isArray(parsed['errors']) && parsed['errors'].length > 0) {
      throw new Error('provider_identity_missing');
    }
    const data = parsed['data'];
    const viewer = isRecord(data) ? data['viewer'] : undefined;
    const organization = isRecord(viewer) ? viewer['organization'] : undefined;
    if (!isRecord(viewer) || !isRecord(organization)) {
      throw new Error('provider_identity_missing');
    }
    return {
      sourceUserId: this.requireId(viewer['id']),
      externalTenantId: this.requireId(organization['id']),
    };
  }

  private requireId(value: unknown): string {
    if (typeof value !== 'string' && typeof value !== 'number') {
      throw new Error('provider_identity_missing');
    }
    const id = String(value);
    if (!id || Buffer.byteLength(id) > ID_MAX_BYTES) {
      throw new Error('provider_identity_missing');
    }
    return id;
  }

  private requireToken(value: unknown): string {
    if (typeof value !== 'string' || !value || Buffer.byteLength(value) > TOKEN_VALUE_MAX_BYTES) {
      throw new Error('provider_token_response_invalid');
    }
    return value;
  }

  private async parse(response: Response): Promise<unknown> {
    try {
      const bytes = await response.arrayBuffer();
      if (bytes.byteLength > TOKEN_MAX_BYTES) throw new Error('provider_response_too_large');
      const text = Buffer.from(bytes).toString('utf8');
      const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim();
      if (contentType === 'application/x-www-form-urlencoded') {
        return Object.fromEntries(new URLSearchParams(text).entries());
      }
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error('provider_response_invalid');
    }
  }

  private githubAppJwt(appId: string, privateKey: string): string {
    const now = Math.floor(Date.now() / 1000);
    const encode = (value: string): string => Buffer.from(value).toString('base64url');
    const header = encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
    const signer = createSign('RSA-SHA256');
    signer.update(`${header}.${payload}`);
    return `${header}.${payload}.${signer.sign(privateKey).toString('base64url')}`;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
