/** Drives one connector pull() pass entirely inside the enclave — plaintext never leaves the enclave. */
import { randomBytes } from 'node:crypto';
import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import type { S3Client } from '@aws-sdk/client-s3';
import type { Logger } from '@folklore/core';
import {
  code,
  type CodebaseRepositorySelection,
  type Connector,
  createPullConnector,
  type PullConnectorDeps,
  type PullOptions,
  type SyncCursor,
} from '@folklore/connectors';
import {
  oauthRefreshCommandSchema,
  type OAuthRefreshCommand,
  type OAuthRefreshMetadataUpdate,
  type PullDueMessage,
} from '@folklore/contracts/enclave';
import { externalHttpsProxyAgent } from '../egress/proxy.js';
import { ProviderRejectedError } from '../egress/provider-token-fetch.js';
import { deriveSourceId } from '@folklore/utils';
import { logger } from '../logger.js';
import type { Pipeline, ProcessedFact } from '../pipeline/index.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { GitHubCodebaseConnectionResolver } from '../codebase/GitHubCodebaseConnectionResolver.js';
import type { CodebaseSelectionStore } from '../codebase/CodebaseSelectionStore.js';
import {
  getDecryptedConnectionForKind,
  type DecryptedSourceConnection,
} from './source-connections-client.js';
import type { JiraWebhookLifecycleService } from './JiraWebhookLifecycleService.js';
import { S3PullCursorStore } from './S3PullCursorStore.js';

export type { PullDueMessage };

export type PullConnectionMetadata = Pick<
  DecryptedSourceConnection,
  | 'externalTenantId'
  | 'webhookRouteId'
  | 'webhookRevision'
  | 'webhookRegistrationIds'
  | 'webhookExpiresAt'
  | 'webhookStatus'
  | 'webhookLastOperation'
  | 'webhookLastAttemptedAt'
  | 'webhookLastSucceededAt'
  | 'webhookLastDeliveryAt'
  | 'webhookProtocolCapture'
  | 'webhookProtocolCaptureExpiresAt'
  | 'webhookFailureCode'
  | 'webhookCleanupRouteId'
  | 'webhookCleanupExternalTenantId'
  | 'webhookCleanupRegistrationIds'
  | 'webhookCleanupExpiresAt'
>;

// Content-free completion signal the worker uses to advance sync health; the
// enclave has no DB access, so this is how last_successful_sync_at gets written worker-side.
export interface PullCompleteSignal {
  type: 'pull-complete';
  orgId: string;
  sourceKind: string;
  sourceId: string;
  completedAt: string;
  backfillLeaseToken?: string;
}

export interface PullFailedSignal {
  type: 'pull-failed';
  orgId: string;
  sourceKind: string;
  sourceId: string;
  failedAt: string;
  backfillLeaseToken?: string;
}

export function buildPullCompleteSignal(
  message: PullDueMessage,
  completedAt: Date = new Date(),
): PullCompleteSignal {
  const backfillLeaseToken =
    'backfillLeaseToken' in message ? message.backfillLeaseToken : undefined;
  return {
    type: 'pull-complete',
    orgId: message.tenant_id,
    sourceKind: message.kind,
    sourceId: message.sourceId,
    completedAt: completedAt.toISOString(),
    ...(backfillLeaseToken ? { backfillLeaseToken } : {}),
  };
}

export function buildPullFailedSignal(message: PullDueMessage, failedAt: Date): PullFailedSignal {
  const backfillLeaseToken =
    'backfillLeaseToken' in message ? message.backfillLeaseToken : undefined;
  return {
    type: 'pull-failed',
    orgId: message.tenant_id,
    sourceKind: message.kind,
    sourceId: message.sourceId,
    failedAt: failedAt.toISOString(),
    ...(backfillLeaseToken ? { backfillLeaseToken } : {}),
  };
}

// the enclave (not the worker signal) owns the uniform 12-month backfill horizon,
// so no wire message can widen how far back a pull reaches.
const BACKFILL_WINDOW_MONTHS = 12;

export interface PullWindow {
  cursor: SyncCursor;
  options: PullOptions;
}

/** Backfill resets the cursor to re-pull from the 12-month window start; otherwise resume from it. */
export function resolvePullWindow(
  backfill: boolean,
  storedCursor: string | null,
  now: Date = new Date(),
): PullWindow {
  const since = new Date(now);
  since.setUTCMonth(since.getUTCMonth() - BACKFILL_WINDOW_MONTHS);
  return { cursor: { value: backfill ? null : storedCursor }, options: { since } };
}

export interface PullRunnerDeps {
  ssm: SSMClient;
  s3?: S3Client;
  processedBucket?: string;
  crypto: EnclaveCrypto;
  orgId: string;
  controlPlaneUrl: string;
  controlPlaneFetch: typeof globalThis.fetch;
  runtimeDeploymentId?: string;
  deploymentId: string;
  agentToken: string;
  pipeline: Pipeline;
  refreshOAuthCredential?: (input: OAuthRefreshCommand) => Promise<OAuthRefreshMetadataUpdate>;
  jiraWebhookLifecycle?: Pick<JiraWebhookLifecycleService, 'reconcile'>;
  mintGitHubInstallationToken?: (input: {
    installationId: string;
  }) => Promise<{ accessToken: string; expiresAt: string }>;
  codebaseSelectionStore?: Pick<CodebaseSelectionStore, 'read'>;
}

export type PullRunResult =
  | {
      outcome: 'processed';
      facts: ProcessedFact[];
      cursor: string | null;
      sourceId: string;
      sourceKind: string;
      persistCursor(): Promise<void>;
    }
  | {
      outcome: 'not_processed';
      reason:
        | 'connection_missing'
        | 'token_missing'
        | 'connector_missing'
        | 'routing_invalid'
        | 'connection_fetch_failed'
        | 'connection_response_invalid'
        | 'connection_integrity_failed'
        | 'connection_decrypt_failed';
      sourceId: string;
      sourceKind: string;
    }
  | {
      outcome: 'superseded';
      sourceId: string;
      sourceKind: string;
    };

const consoleLogger: Logger = logger;

function parseAllowlist(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function cursorSsmPath(tenantId: string, sourceId: string): string {
  return `/folklore/${tenantId}/pull-cursor/${sourceId}`;
}

async function loadCursor(
  ssm: SSMClient,
  tenantId: string,
  sourceId: string,
): Promise<string | null> {
  try {
    const resp = await ssm.send(
      new GetParameterCommand({ Name: cursorSsmPath(tenantId, sourceId) }),
    );
    return resp.Parameter?.Value ?? null;
  } catch (error) {
    if (isParameterNotFound(error)) return null;
    throw error;
  }
}

function isParameterNotFound(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'ParameterNotFound'
  );
}

async function saveCursor(
  ssm: SSMClient,
  tenantId: string,
  sourceId: string,
  value: string | null,
): Promise<void> {
  if (value === null) return;
  await ssm.send(
    new PutParameterCommand({
      Name: cursorSsmPath(tenantId, sourceId),
      Value: value,
      Type: 'String',
      Overwrite: true,
    }),
  );
}

// `code` cursors outgrow the 4 KB SSM Standard tier (per-repo completion map) and carry raw file
// paths, so they persist ESDK-sealed in the tenant's processed bucket instead — enclave-write,
// enclave-read, worker can't decrypt. The SSM medium stays untouched for every other kind.
async function loadCodeCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
): Promise<string | null> {
  return codeCursorStore(deps).load(message.sourceId);
}

async function saveCodeCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
  value: string | null,
): Promise<void> {
  await codeCursorStore(deps).save(message.sourceId, value);
}

function codeCursorStore(deps: PullRunnerDeps): S3PullCursorStore {
  if (!deps.s3 || !deps.processedBucket) throw new Error('code_pull_cursor_store_unavailable');
  return new S3PullCursorStore({
    s3: deps.s3,
    crypto: deps.crypto,
    bucket: deps.processedBucket,
    orgId: deps.orgId,
    deploymentId: deps.deploymentId,
  });
}

/** One tick per attempt, owned by exactly one site: the connector on completion, the runner on early returns. */
export function advanceCodeCursorTick(cursorValue: string | null): string {
  const cursor = code.parseCodeCursor(cursorValue);
  return JSON.stringify({ ...cursor, tick: cursor.tick + 1 });
}

const MINT_TOKEN_TTL_MS = 50 * 60 * 1000;
const MINT_TOKEN_CACHE_MAX_ENTRIES = 128;

interface MintedInstallationToken {
  accessToken: Buffer;
  mintedAt: number;
}

const mintedTokenCache = new Map<string, MintedInstallationToken>();
const mintedTokenEpochByOrg = new Map<string, number>();

function deleteMintedToken(cacheKey: string): void {
  const token = mintedTokenCache.get(cacheKey);
  if (!token) return;
  token.accessToken.fill(0);
  mintedTokenCache.delete(cacheKey);
}

function sweepExpiredMintedTokens(now: number): void {
  for (const [cacheKey, token] of mintedTokenCache) {
    if (now - token.mintedAt >= MINT_TOKEN_TTL_MS) deleteMintedToken(cacheKey);
  }
}

function cacheMintedToken(cacheKey: string, accessToken: string, mintedAt: number): void {
  deleteMintedToken(cacheKey);
  while (mintedTokenCache.size >= MINT_TOKEN_CACHE_MAX_ENTRIES) {
    const oldestKey = mintedTokenCache.keys().next().value as string | undefined;
    if (!oldestKey) break;
    deleteMintedToken(oldestKey);
  }
  mintedTokenCache.set(cacheKey, { accessToken: Buffer.from(accessToken, 'utf8'), mintedAt });
}

/** Test seam: the mint cache is enclave-process-lifetime by design (module-level). */
export function resetMintedTokenCache(): void {
  for (const cacheKey of [...mintedTokenCache.keys()]) deleteMintedToken(cacheKey);
  mintedTokenEpochByOrg.clear();
}

/** Drops all org-bound minted GitHub tokens and overwrites their in-memory buffers. */
export function evictMintedTokensForOrg(orgId: string): void {
  mintedTokenEpochByOrg.set(orgId, (mintedTokenEpochByOrg.get(orgId) ?? 0) + 1);
  const prefix = `github-installation:${orgId}:`;
  for (const cacheKey of mintedTokenCache.keys()) {
    if (cacheKey.startsWith(prefix)) deleteMintedToken(cacheKey);
  }
}

function isRateLimitedMintStatus(status: number): boolean {
  return status === 403 || status === 422;
}

export type GitHubMintOutcome =
  | { outcome: 'token'; accessToken: string }
  | { outcome: 'rate_limited' };

// Shared by resolveSourceToken AND the 401-retry path. The retry path forces a fresh mint
// (bypassCache) because a cached token can expire or be revoked mid-pull; write-through replaces
// the revoked entry. The connect-time service (EnclaveGitHubInstallationTokenService) does NOT
// share this helper — connect is rare and its loud failure is correct.
async function mintGitHubInstallationTokenForPull(
  installationId: string | undefined,
  mint: PullRunnerDeps['mintGitHubInstallationToken'],
  scope: { orgId: string; connectionId: string; connectionGeneration: string },
  options: { bypassCache?: boolean } = {},
): Promise<GitHubMintOutcome> {
  if (!mint) throw new Error('github_installation_token_minting_unavailable');
  if (!installationId) throw new Error('github_installation_id_missing');
  const cacheKey = `github-installation:${scope.orgId}:${scope.connectionId}:${installationId}:${scope.connectionGeneration}`;
  const now = Date.now();
  const mintEpoch = mintedTokenEpochByOrg.get(scope.orgId) ?? 0;
  sweepExpiredMintedTokens(now);
  if (!options.bypassCache) {
    const cached = mintedTokenCache.get(cacheKey);
    if (cached) {
      mintedTokenCache.delete(cacheKey);
      mintedTokenCache.set(cacheKey, cached);
      return { outcome: 'token', accessToken: cached.accessToken.toString('utf8') };
    }
  }
  try {
    const minted = await mint({ installationId });
    if (!minted.accessToken) throw new Error('github_mint_failed');
    if ((mintedTokenEpochByOrg.get(scope.orgId) ?? 0) === mintEpoch) {
      cacheMintedToken(cacheKey, minted.accessToken, Date.now());
    }
    return { outcome: 'token', accessToken: minted.accessToken };
  } catch (err) {
    if (err instanceof ProviderRejectedError && isRateLimitedMintStatus(err.status)) {
      return { outcome: 'rate_limited' };
    }
    throw err;
  }
}

export async function resolveSourceToken(
  kind: string,
  connection: Pick<DecryptedSourceConnection, 'accessToken' | 'kind' | 'installationId'> &
    Partial<
      Pick<
        DecryptedSourceConnection,
        'connectionId' | 'activationGeneration' | 'attestationGeneration'
      >
    >,
  mintGitHubInstallationToken?: PullRunnerDeps['mintGitHubInstallationToken'],
  scope: { orgId: string } = { orgId: 'unscoped' },
): Promise<string | null> {
  if (kind !== 'github' && kind !== 'code') return connection.accessToken;
  if (!connection.connectionId || !connection.activationGeneration) {
    throw new Error('github_connection_binding_missing');
  }
  const minted = await mintGitHubInstallationTokenForPull(
    connection.installationId,
    mintGitHubInstallationToken,
    {
      orgId: scope.orgId,
      connectionId: connection.connectionId,
      connectionGeneration: connection.activationGeneration,
    },
  );
  if (minted.outcome === 'rate_limited') {
    // github stays loud (DLQ alarm); a `code` mint-403 is a non-throwing early return the
    // runner turns into a cursor tick bump (scheduler cadence is fixed, no backoff to rely on).
    if (kind === 'code') return null;
    throw new Error('github_mint_rate_limited');
  }
  return minted.accessToken;
}

// Every client here MUST egress via the proxy — either the global undici dispatcher
// (fetch-based SDKs) or an explicit agent (axios/node:http SDKs like Slack), else its
// pull dials the internet directly and fails closed on real hardware.
export function buildConnector(
  kind: string,
  token: string,
  connectionMetadata?: PullConnectionMetadata,
  codebaseSelection?: CodebaseRepositorySelection,
): Connector | null {
  const deps: PullConnectorDeps = {
    logger: consoleLogger,
    token,
    ...(connectionMetadata?.externalTenantId
      ? { externalTenantId: connectionMetadata.externalTenantId }
      : {}),
    httpsProxyAgent: externalHttpsProxyAgent(),
    gmailLabelAllowlist: parseAllowlist(process.env['EMAIL_GMAIL_LABEL_ALLOWLIST']),
    m365FolderAllowlist: parseAllowlist(process.env['EMAIL_M365_FOLDER_ALLOWLIST']),
    ...(codebaseSelection ? { codebaseSelection } : {}),
  };
  return createPullConnector(kind, deps);
}

/** Handles a single content-free `pull-due` signal end to end, in-enclave. */
export async function runPull(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connectorBuilder: (
    kind: string,
    token: string,
    connectionMetadata: PullConnectionMetadata,
    codebaseSelection?: CodebaseRepositorySelection,
  ) => Connector | null = buildConnector,
): Promise<PullRunResult> {
  if (
    message.tenant_id !== deps.orgId ||
    message.sourceId !== deriveSourceId(deps.orgId, message.kind)
  ) {
    return notProcessed(message, 'routing_invalid');
  }
  const resolved =
    message.kind === 'code'
      ? await resolveCodebaseConnection(deps)
      : await getDecryptedConnectionForKind(
          deps.controlPlaneUrl,
          deps.runtimeDeploymentId ?? deps.deploymentId,
          deps.deploymentId,
          deps.agentToken,
          message.kind,
          deps.orgId,
          deps.crypto,
          deps.controlPlaneFetch,
        );
  if (resolved.outcome === 'not_ready') return superseded(message);
  if (resolved.outcome === 'not_processed') {
    return notProcessed(message, resolved.reason);
  }
  if (resolved.outcome === 'missing') {
    if (message.trigger === 'activation') return superseded(message);
    return notProcessed(message, 'connection_missing');
  }
  const connection = resolved.connection;
  const activationGeneration =
    resolved.outcome === 'ready' ? resolved.capabilityGeneration : connection.activationGeneration;
  const codebaseSelection =
    resolved.outcome === 'ready' ? selectionForCodeConnector(resolved.selection) : undefined;
  if (message.trigger === 'activation' && message.activationGeneration !== activationGeneration) {
    return superseded(message);
  }

  const isCode = message.kind === 'code';
  // The code cursor loads BEFORE the mint so a mint-403 early return can bump its tick.
  const storedCursor = isCode ? await loadCodeCursor(deps, message) : null;

  const token = await resolveSourceToken(
    message.kind,
    connection,
    deps.mintGitHubInstallationToken,
    { orgId: deps.orgId },
  );
  if (!token) {
    return notProcessed(message, 'token_missing');
  }
  const connector = buildPullConnector(
    connectorBuilder,
    message.kind,
    token,
    connectionMetadata(connection),
    codebaseSelection,
  );
  if (!connector) {
    return notProcessed(message, 'connector_missing');
  }

  const window = resolvePullWindow(
    message.backfill,
    isCode ? storedCursor : await loadCursor(deps.ssm, message.tenant_id, message.sourceId),
  );
  const result = await pullWithRefresh(
    message,
    deps,
    connection,
    connector,
    window,
    connectorBuilder,
    codebaseSelection,
  );

  const cursor = result.earlyReturn
    ? advanceCodeCursorTick(result.cursor.value)
    : result.cursor.value;
  await reconcileJiraWebhook(message, deps, result.connection);
  const facts = await deps.pipeline.handlePulled(result.facts, result.containers, message.kind);
  return {
    outcome: 'processed',
    facts,
    cursor,
    sourceId: message.sourceId,
    sourceKind: message.kind,
    persistCursor: async () => {
      if (isCode) {
        await saveCodeCursor(deps, message, cursor);
        return;
      }
      await saveCursor(deps.ssm, message.tenant_id, message.sourceId, cursor);
    },
  };
}

async function resolveCodebaseConnection(deps: PullRunnerDeps) {
  if (!deps.codebaseSelectionStore) {
    return { outcome: 'not_ready' as const, reason: 'codebase_selection_missing' as const };
  }
  return new GitHubCodebaseConnectionResolver({
    controlPlaneUrl: deps.controlPlaneUrl,
    runtimeDeploymentId: deps.runtimeDeploymentId ?? deps.deploymentId,
    tenantDeploymentId: deps.deploymentId,
    agentToken: deps.agentToken,
    orgId: deps.orgId,
    crypto: deps.crypto,
    fetchImpl: deps.controlPlaneFetch,
    selectionStore: deps.codebaseSelectionStore,
  }).resolveScheduled();
}

function selectionForCodeConnector(
  selection: Awaited<ReturnType<CodebaseSelectionStore['read']>>,
): CodebaseRepositorySelection {
  if (selection.mode === 'all') return { mode: 'all' };
  return {
    mode: 'selected',
    repositoryIds: selection.repositories.map((repository) => repository.id),
  };
}

function buildPullConnector(
  connectorBuilder: (
    kind: string,
    token: string,
    connectionMetadata: PullConnectionMetadata,
    codebaseSelection?: CodebaseRepositorySelection,
  ) => Connector | null,
  kind: string,
  token: string,
  connectionMetadata: PullConnectionMetadata,
  codebaseSelection?: CodebaseRepositorySelection,
): Connector | null {
  if (codebaseSelection) {
    return connectorBuilder(kind, token, connectionMetadata, codebaseSelection);
  }
  return connectorBuilder(kind, token, connectionMetadata);
}

function superseded(message: PullDueMessage): PullRunResult {
  return { outcome: 'superseded', sourceId: message.sourceId, sourceKind: message.kind };
}

function notProcessed(
  message: PullDueMessage,
  reason: Extract<PullRunResult, { outcome: 'not_processed' }>['reason'],
): PullRunResult {
  return { outcome: 'not_processed', reason, sourceId: message.sourceId, sourceKind: message.kind };
}

export async function pullWithRefresh(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connection: DecryptedSourceConnection,
  connector: Connector,
  window: PullWindow,
  connectorBuilder: (
    kind: string,
    token: string,
    connectionMetadata: PullConnectionMetadata,
    codebaseSelection?: CodebaseRepositorySelection,
  ) => Connector | null = buildConnector,
  codebaseSelection?: CodebaseRepositorySelection,
) {
  try {
    return {
      ...(await connector.pull(window.cursor, window.options)),
      connection,
    };
  } catch (error) {
    if (!isUnauthorized(error)) throw error;
    if (connection.kind === 'github' || connection.kind === 'code') {
      return retryPullWithFreshGitHubToken(
        deps,
        message.kind,
        connection,
        window,
        connectorBuilder,
        error,
        codebaseSelection,
      );
    }
    if (!deps.refreshOAuthCredential) throw error;
    if (!connection.encryptedRefreshToken || !connection.refreshCiphertextSha256) throw error;
    const command = oauthRefreshCommandSchema.parse({
      encryptedRefreshToken: connection.encryptedRefreshToken,
      orgId: deps.orgId,
      deploymentId: deps.deploymentId,
      sourceKind: message.kind,
      connectionId: connection.connectionId,
      activationGeneration: connection.activationGeneration,
      attestationGeneration: connection.attestationGeneration,
      attemptId: randomBytes(32).toString('hex'),
      expectedRefreshCiphertextSha256: connection.refreshCiphertextSha256,
    });
    try {
      const refresh = await deps.refreshOAuthCredential(command);
      if (refresh.outcome !== 'success') throw error;
    } catch {
      throw error;
    }
    const refreshedResolution = await getDecryptedConnectionForKind(
      deps.controlPlaneUrl,
      deps.runtimeDeploymentId ?? deps.deploymentId,
      deps.deploymentId,
      deps.agentToken,
      message.kind,
      deps.orgId,
      deps.crypto,
      deps.controlPlaneFetch,
    );
    if (refreshedResolution.outcome !== 'connected') throw error;
    const refreshed = refreshedResolution.connection;
    if (refreshed.activationGeneration !== connection.activationGeneration) throw error;
    const refreshedToken = await resolveSourceToken(message.kind, refreshed, undefined, {
      orgId: deps.orgId,
    });
    if (!refreshedToken) throw error;
    const refreshedConnector = buildPullConnector(
      connectorBuilder,
      message.kind,
      refreshedToken,
      connectionMetadata(refreshed),
      codebaseSelection,
    );
    if (!refreshedConnector) throw error;
    return {
      ...(await refreshedConnector.pull(window.cursor, window.options)),
      connection: refreshed,
    };
  }
}

// A github/code pull has no refresh token: re-mint the ~1h install token and retry once.
// The retry mint bypasses the TTL cache — recovery is always a fresh mint.
async function retryPullWithFreshGitHubToken(
  deps: PullRunnerDeps,
  sourceKind: string,
  connection: DecryptedSourceConnection,
  window: PullWindow,
  connectorBuilder: (
    kind: string,
    token: string,
    connectionMetadata: PullConnectionMetadata,
    codebaseSelection?: CodebaseRepositorySelection,
  ) => Connector | null,
  originalError: unknown,
  codebaseSelection?: CodebaseRepositorySelection,
) {
  if (!deps.mintGitHubInstallationToken || !connection.installationId) throw originalError;
  const minted = await mintGitHubInstallationTokenForPull(
    connection.installationId,
    deps.mintGitHubInstallationToken,
    {
      orgId: deps.orgId,
      connectionId: connection.connectionId,
      connectionGeneration: connection.activationGeneration,
    },
    { bypassCache: true },
  );
  if (minted.outcome === 'rate_limited') {
    if (sourceKind === 'code') {
      return {
        facts: [],
        containers: [],
        cursor: window.cursor,
        hasMore: false,
        earlyReturn: true,
        connection,
      };
    }
    throw new Error('github_mint_rate_limited');
  }
  const connector = buildPullConnector(
    connectorBuilder,
    sourceKind,
    minted.accessToken,
    connectionMetadata(connection),
    codebaseSelection,
  );
  if (!connector) throw originalError;
  return {
    ...(await connector.pull(window.cursor, window.options)),
    connection,
  };
}

async function reconcileJiraWebhook(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connection: DecryptedSourceConnection,
): Promise<void> {
  if (message.kind !== 'jira' || !deps.jiraWebhookLifecycle) return;
  if (!connection.externalTenantId || !connection.webhookRouteId) return;
  try {
    await deps.jiraWebhookLifecycle.reconcile({
      runtimeDeploymentId: deps.runtimeDeploymentId ?? deps.deploymentId,
      tenantDeploymentId: deps.deploymentId,
      orgId: deps.orgId,
      connectionId: connection.connectionId,
      sourceKind: connection.kind,
      attestationGeneration: connection.attestationGeneration,
      externalTenantId: connection.externalTenantId,
      accessToken: connection.accessToken,
      webhookRouteId: connection.webhookRouteId,
      webhookRevision: connection.webhookRevision,
      webhookRegistrationIds: connection.webhookRegistrationIds,
      webhookExpiresAt: connection.webhookExpiresAt,
      webhookStatus: connection.webhookStatus,
      webhookLastAttemptedAt: connection.webhookLastAttemptedAt,
      webhookCleanupRouteId: connection.webhookCleanupRouteId,
      webhookCleanupExternalTenantId: connection.webhookCleanupExternalTenantId,
      webhookCleanupRegistrationIds: connection.webhookCleanupRegistrationIds,
    });
  } catch {
    console.warn('pull-due: jira webhook reconciliation degraded');
  }
}

function connectionMetadata(connection: DecryptedSourceConnection): PullConnectionMetadata {
  return {
    externalTenantId: connection.externalTenantId,
    webhookRouteId: connection.webhookRouteId,
    webhookRevision: connection.webhookRevision,
    webhookRegistrationIds: connection.webhookRegistrationIds,
    webhookExpiresAt: connection.webhookExpiresAt,
    webhookStatus: connection.webhookStatus,
    webhookLastOperation: connection.webhookLastOperation,
    webhookLastAttemptedAt: connection.webhookLastAttemptedAt,
    webhookLastSucceededAt: connection.webhookLastSucceededAt,
    webhookLastDeliveryAt: connection.webhookLastDeliveryAt,
    webhookProtocolCapture: connection.webhookProtocolCapture,
    webhookProtocolCaptureExpiresAt: connection.webhookProtocolCaptureExpiresAt,
    webhookFailureCode: connection.webhookFailureCode,
    webhookCleanupRouteId: connection.webhookCleanupRouteId,
    webhookCleanupExternalTenantId: connection.webhookCleanupExternalTenantId,
    webhookCleanupRegistrationIds: connection.webhookCleanupRegistrationIds,
    webhookCleanupExpiresAt: connection.webhookCleanupExpiresAt,
  };
}

function isUnauthorized(error: unknown, seen = new Set<object>()): boolean {
  if (typeof error !== 'object' || error === null) return false;
  if (seen.has(error)) return false;
  seen.add(error);
  const value = error as Record<string, unknown>;
  if (value['status'] === 401 || value['statusCode'] === 401 || value['httpStatus'] === 401) {
    return true;
  }
  return isUnauthorized(value['cause'], seen);
}
