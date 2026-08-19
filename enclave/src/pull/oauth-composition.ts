import { matchesSpkiPin, verifyControlPlaneCertificate } from '@folklore/utils';
import type { S3Client } from '@aws-sdk/client-s3';
import { ProxyAgent } from 'undici';
import { z } from 'zod';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import type { TenantContext } from '../tenant/tenant-context.js';
import { assertControlPlaneOrigin } from './control-plane-url.js';
import { EnclaveGitHubInstallationTokenService } from './EnclaveGitHubInstallationTokenService.js';
import { EnclaveOAuthAuthorizationService } from './EnclaveOAuthAuthorizationService.js';
import { EnclaveOAuthCredentialSealer } from './EnclaveOAuthCredentialSealer.js';
import { EnclaveOAuthIngress, type EnclaveOAuthIngressHandlers } from './EnclaveOAuthIngress.js';
import { EnclaveOAuthRefreshService } from './EnclaveOAuthRefreshService.js';
import { HttpOAuthCredentialPersistence } from './HttpOAuthCredentialPersistence.js';
import { HttpOAuthLeaseResolver } from './HttpOAuthLeaseResolver.js';
import { HttpOAuthPersistenceTransport } from './HttpOAuthPersistenceTransport.js';
import { HttpOAuthStateGuard } from './HttpOAuthStateGuard.js';
import { HttpProviderTokenClient } from './HttpProviderTokenClient.js';
import { EnclaveProviderRefreshSecretLoader } from './EnclaveProviderRefreshSecretLoader.js';
import { EGRESS_PROXY_PORT } from '../egress/proxy.js';
import {
  assertStablePublicAddresses,
  type ProviderTokenFetchOptions,
} from '../egress/provider-token-fetch.js';
import { HttpJiraWebhookClient } from './HttpJiraWebhookClient.js';
import {
  JiraWebhookLifecycleService,
  type JiraWebhookMode,
} from './JiraWebhookLifecycleService.js';
import { JiraWebhookDisconnectService } from './JiraWebhookDisconnectService.js';
import {
  JiraWebhookAuthenticator,
  type JiraWebhookClaimPolicy,
} from '../ingest/JiraWebhookAuthenticator.js';
import { S3JiraWebhookReplayStore } from '../ingest/S3JiraWebhookReplayStore.js';
import type { OAuthRefreshCommand, OAuthRefreshMetadataUpdate } from '@folklore/contracts/enclave';
import type { WebhookLifecycleDelivery } from '@folklore/contracts/enclave';
import type { VerifiedProviderConfig } from '../egress/provider-token-fetch.js';
import {
  bootManifestOAuthProviderSchema,
  controlPlaneIdentitySchema,
  type BootManifestOAuthProvider,
  type ControlPlaneIdentity,
} from '@folklore/contracts/enclave-attestation';

type ControlPlaneIdentityInput = Omit<ControlPlaneIdentity, 'tlsSpkiSha256'> & {
  readonly tlsSpkiSha256: readonly string[];
};
type OAuthManifestProviderInput = Omit<
  BootManifestOAuthProvider,
  'allowedHosts' | 'jiraWebhookPilotOrgIds' | 'jiraWebhookClaimPolicy'
> & {
  readonly allowedHosts: readonly string[];
  readonly jiraWebhookPilotOrgIds?: readonly string[];
  readonly jiraWebhookClaimPolicy?: Readonly<
    NonNullable<BootManifestOAuthProvider['jiraWebhookClaimPolicy']>
  >;
};

const providerConfigSchema = z
  .object({
    kind: z.string().min(1).max(64),
    tokenEndpoint: z.string().url(),
    identityEndpoint: z.string().url(),
    githubInstallationEndpoint: z
      .string()
      .min(1)
      .max(2_048)
      .refine((value) => {
        if (value.match(/\{installationId\}/g)?.length !== 1) return false;
        try {
          const url = new URL(value.replace('{installationId}', '0'));
          return url.protocol === 'https:' && url.username === '' && url.password === '';
        } catch {
          return false;
        }
      }, 'github installation endpoint must contain one exact HTTPS {installationId} placeholder'),
    oauthSecretRef: z.string().min(1).max(512),
    allowedHosts: z.array(z.string().min(1).max(253)).min(1).max(16),
  })
  .strict();

export interface OAuthCompositionOptions {
  controlPlaneUrl: string;
  controlPlaneIdentity?: ControlPlaneIdentityInput;
  readControlPlaneSpkiSha256?: () => Promise<string>;
  deploymentId: string;
  agentToken: () => string;
  authorizationToken: string;
  providerConfigJson?: string;
  providerConfigs?: readonly OAuthManifestProviderInput[];
  allowUnverifiedProviderConfig?: boolean;
  resolveTenant(orgId: string): TenantContext;
  getSecretValue(input: { secretId: string }): Promise<Uint8Array>;
  kmsKeyId: string;
  s3?: S3Client;
  fetchImpl?: typeof globalThis.fetch;
  jiraWebhookMode?: JiraWebhookMode;
  jiraWebhookPilotOrgIds?: readonly string[];
  jiraWebhookClaimPolicy?: JiraWebhookClaimPolicy;
}

export interface OAuthRuntime {
  ingress: EnclaveOAuthIngress;
  refreshOAuthCredential(input: OAuthRefreshCommand): Promise<OAuthRefreshMetadataUpdate>;
  mintGitHubInstallationToken(input: {
    installationId: string;
  }): Promise<{ accessToken: string; expiresAt: string }>;
  jiraWebhookLifecycle: JiraWebhookLifecycleService;
  jiraWebhookAuthenticator: JiraWebhookAuthenticator;
  recordJiraWebhookDelivery(
    input: WebhookLifecycleDelivery,
  ): Promise<'updated' | 'stale' | 'invalid_submission'>;
}

/** Composes the production OAuth path; missing secrets/configuration throws before BoxServer starts. */
export function createOAuthRuntime(options: OAuthCompositionOptions): OAuthRuntime {
  const jiraWebhookMode = options.jiraWebhookMode ?? options.jiraWebhookClaimPolicy?.mode ?? 'off';
  const jiraWebhookEnabledOrgIds = new Set(options.jiraWebhookPilotOrgIds ?? []);
  if (jiraWebhookMode === 'enabled' && !options.s3) {
    throw new Error('jira_webhook_replay_store_unavailable');
  }
  const configs = parseProviderConfigs(
    options.providerConfigJson,
    options.providerConfigs,
    options.allowUnverifiedProviderConfig ?? false,
  );
  if (!options.kmsKeyId) {
    throw new Error('provider_secret_decrypt_configuration_unavailable');
  }
  const identity = options.controlPlaneIdentity
    ? controlPlaneIdentitySchema.parse(options.controlPlaneIdentity)
    : undefined;
  if (!identity) {
    throw new Error('control_plane_identity_verifier_unavailable');
  }
  if (new URL(options.controlPlaneUrl).origin !== identity.origin) {
    throw new Error('control_plane_identity_mismatch');
  }
  const controlPlaneFetch = createPinnedControlPlaneFetch(
    options.fetchImpl ?? globalThis.fetch,
    identity,
    options.readControlPlaneSpkiSha256,
  );
  const providerFetchOptions: ProviderTokenFetchOptions = {
    assertProxyResolution: assertStablePublicAddresses,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
  };
  const providerSecrets = new EnclaveProviderRefreshSecretLoader(
    { getSecretValue: options.getSecretValue },
    options.kmsKeyId,
  );
  const provider = new HttpProviderTokenClient(providerSecrets, providerFetchOptions);
  const leaseResolver = new HttpOAuthLeaseResolver(
    options.controlPlaneUrl,
    options.deploymentId,
    options.agentToken,
    controlPlaneFetch,
  );
  const stateGuard = new HttpOAuthStateGuard(
    options.controlPlaneUrl,
    options.deploymentId,
    options.agentToken,
    controlPlaneFetch,
  );
  const transport = new HttpOAuthPersistenceTransport(
    options.controlPlaneUrl,
    options.deploymentId,
    options.agentToken,
    controlPlaneFetch,
  );
  const persistence = new HttpOAuthCredentialPersistence(transport);
  const jiraWebhookLifecycle = new JiraWebhookLifecycleService(
    new HttpJiraWebhookClient(providerFetchOptions),
    persistence,
    {
      mode: jiraWebhookMode,
      isEnabledForOrg: (orgId) => jiraWebhookEnabledOrgIds.has(orgId),
    },
  );
  const jiraWebhookReplayStore = options.s3
    ? new S3JiraWebhookReplayStore(options.s3, options.resolveTenant)
    : undefined;
  const jiraWebhookDisconnect = new JiraWebhookDisconnectService(
    new HttpJiraWebhookClient(providerFetchOptions),
    persistence,
    jiraWebhookReplayStore,
  );
  const jiraWebhookAuthenticator = new JiraWebhookAuthenticator({
    ...options.jiraWebhookClaimPolicy,
    mode: jiraWebhookMode,
    loadClientSecret: async () => {
      const config = configs.get('jira');
      if (!config) throw new Error('jira_provider_not_configured');
      return (await providerSecrets.load(config)).clientSecret;
    },
    ...(jiraWebhookReplayStore
      ? {
          reserveReplay: (input: Parameters<S3JiraWebhookReplayStore['reserve']>[0]) =>
            jiraWebhookReplayStore.reserve(input),
          commitReplay: (input: Parameters<S3JiraWebhookReplayStore['commit']>[0]) =>
            jiraWebhookReplayStore.commit(input),
          releaseReplay: (input: Parameters<S3JiraWebhookReplayStore['release']>[0]) =>
            jiraWebhookReplayStore.release(input),
        }
      : {}),
  });
  const sealer = new EnclaveOAuthCredentialSealer((orgId) =>
    cryptoFor(options.resolveTenant(orgId)),
  );

  const handlers: EnclaveOAuthIngressHandlers = {
    resolveGeneration: (input) => leaseResolver.resolve(input),
    redeemSource: async (input, generation) => {
      const tenant = options.resolveTenant(input.orgId);
      return new EnclaveOAuthAuthorizationService(
        tenant.ingestPrivateKey,
        stateGuard,
        sealer,
        persistence,
        provider,
        (kind) => configs.get(kind) ?? null,
        persistence,
      ).redeem(input, generation);
    },
    redeemMemberIdentity: async (input, generation) => {
      const tenant = options.resolveTenant(input.orgId);
      return new EnclaveOAuthAuthorizationService(
        tenant.ingestPrivateKey,
        stateGuard,
        sealer,
        persistence,
        provider,
        (kind) => configs.get(kind) ?? null,
        persistence,
      ).redeemMemberIdentity(input, generation);
    },
    redeemGitHubInstallation: async (input, generation) => {
      return new EnclaveGitHubInstallationTokenService(
        sealer,
        persistence,
        provider,
        (kind) => configs.get(kind) ?? null,
        stateGuard,
      ).mint({
        ...input,
        generation,
      });
    },
    cleanupDisconnect: async (input) => {
      const tenant = options.resolveTenant(input.orgId);
      await jiraWebhookDisconnect.cleanup(input, tenant.crypto);
    },
  };
  return {
    ingress: new EnclaveOAuthIngress(handlers, {
      authorizationToken: options.authorizationToken,
    }),
    refreshOAuthCredential: async (input) => {
      const tenant = options.resolveTenant(input.orgId);
      return new EnclaveOAuthRefreshService(
        tenant.crypto,
        sealer,
        persistence,
        provider,
        (kind) => configs.get(kind) ?? null,
        leaseResolver,
      ).redeem(input);
    },
    mintGitHubInstallationToken: async (input) => {
      const config = configs.get('github');
      if (!config) throw new Error('github_provider_not_configured');
      return provider.mintGitHubInstallationToken({
        config,
        installationId: input.installationId,
      });
    },
    jiraWebhookLifecycle,
    jiraWebhookAuthenticator,
    recordJiraWebhookDelivery: (input) => persistence.recordWebhookDelivery(input),
  };
}

export function createOAuthIngress(options: OAuthCompositionOptions): EnclaveOAuthIngress {
  return createOAuthRuntime(options).ingress;
}

function cryptoFor(context: TenantContext): EnclaveCrypto {
  return context.crypto;
}

function parseProviderConfigs(
  raw: string | undefined,
  manifestProviders: readonly OAuthManifestProviderInput[] | undefined,
  allowUnverifiedProviderConfig: boolean,
): Map<string, VerifiedProviderConfig> {
  if (manifestProviders) {
    const parsed = manifestProviders
      .map((entry) => bootManifestOAuthProviderSchema.parse(entry))
      .filter((entry) => entry.enabled)
      .map((entry) => ({
        kind: entry.kind,
        tokenEndpoint: entry.tokenEndpoint,
        identityEndpoint: entry.identityEndpoint,
        githubInstallationEndpoint: entry.githubInstallationEndpoint,
        oauthSecretRef: entry.secretReferenceId,
        allowedHosts: entry.allowedHosts,
      }));
    assertUniqueKinds(parsed);
    return new Map(parsed.map((config) => [config.kind, config]));
  }
  if (!raw || !allowUnverifiedProviderConfig) throw new Error('provider_config_unavailable');
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error('provider_config_invalid');
  }
  const list = Array.isArray(value) ? value : Object.values(value ?? {});
  const parsed = list.map((entry) => providerConfigSchema.parse(entry));
  if (parsed.length === 0) throw new Error('provider_config_empty');
  assertUniqueKinds(parsed);
  return new Map(parsed.map((config) => [config.kind, config]));
}

function assertUniqueKinds(configs: readonly VerifiedProviderConfig[]): void {
  if (new Set(configs.map((config) => config.kind)).size !== configs.length) {
    throw new Error('provider_config_duplicate_kind');
  }
}

export function createPinnedControlPlaneFetch(
  fetchImpl: typeof globalThis.fetch,
  identity: ControlPlaneIdentityInput,
  readSpkiSha256?: () => Promise<string>,
): typeof globalThis.fetch {
  assertControlPlaneOrigin(identity.origin);
  const dispatcher = createControlPlaneDispatcher(identity);
  return async (input, init) => {
    const supplied =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    let url: URL;
    try {
      url = new URL(supplied);
    } catch {
      throw new Error('control_plane_url_invalid');
    }
    if (url.origin !== identity.origin) throw new Error('control_plane_origin_mismatch');
    // Test doubles may not execute undici's TLS callback. Keep the seam for those callers, but
    // production's global fetch is pinned by `requestTls.checkServerIdentity` on the same socket
    // that carries the credential-bearing request; there is no preflight HEAD/TOCTOU window.
    if (readSpkiSha256 && fetchImpl !== globalThis.fetch) {
      const actualPin = await readSpkiSha256();
      if (!matchesSpkiPin(identity.tlsSpkiSha256, actualPin)) {
        throw new Error('control_plane_spki_pin_mismatch');
      }
    }
    const response = await fetchImpl(input, {
      ...init,
      redirect: 'manual',
      ...(fetchImpl === globalThis.fetch ? { dispatcher } : {}),
    } as RequestInit & { dispatcher?: ProxyAgent });
    if (response.status >= 300 && response.status < 400) {
      throw new Error('control_plane_redirect_denied');
    }
    return response;
  };
}

function createControlPlaneDispatcher(identity: ControlPlaneIdentityInput): ProxyAgent {
  return new ProxyAgent({
    uri: `http://localhost:${EGRESS_PROXY_PORT}`,
    requestTls: {
      checkServerIdentity: (hostname, certificate) => {
        return verifyControlPlaneCertificate(hostname, certificate, identity.tlsSpkiSha256);
      },
    },
  });
}
