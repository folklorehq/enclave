/** Drives one connector pull() pass entirely inside the enclave — plaintext never leaves the enclave. */
import { randomBytes } from 'node:crypto';
import type { S3Client } from '@aws-sdk/client-s3';
import type { Logger } from '@folklore/core';
import {
  type Connector,
  createPullConnector,
  isSpecConnectorKind,
  type PullConnectorDeps,
  type PullOptions,
  type PullResult,
  type SyncCursor,
} from '@folklore/connectors';
import { NOTION_KIND, isPausableSourceKind, supportsPerPersonMode } from '@folklore/contracts';
import {
  oauthRefreshCommandSchema,
  pullStatsSchema,
  type OAuthRefreshCommand,
  type OAuthRefreshMetadataUpdate,
  type PullCompleteSignal,
  type PullDueMessage,
  type PullFailedSignal,
  type PullFailureReason,
} from '@folklore/contracts/enclave';
import { ConnectorEgressTransport } from '../egress/connector-runtime/ConnectorEgressTransport.js';
import { externalHttpsProxyAgent } from '../egress/proxy.js';
import { ProviderRejectedError } from '../egress/provider-token-fetch.js';
import {
  OAuthRefreshFailedError,
  type FailedOAuthRefreshOutcome,
} from './OAuthRefreshFailedError.js';
import { deriveMemberSourceId, deriveSourceId } from '@folklore/utils';
import { logger } from '../logger.js';
import type { MemberPullScope, Pipeline, ProcessedFact } from '../pipeline/index.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  ADMIT_ALL,
  admissionOf,
  type ResourceAdmission,
} from '../resource-scope/resource-admission.js';
import { ResourceScopeConflictError } from '../resource-scope/resource-scope-errors.js';
import type { ResourceScope } from '../resource-scope/ResourceScopeStore.js';
import type { TenantResourceScope } from '../resource-scope/TenantResourceScope.js';
import {
  getDecryptedConnectionForKind,
  getDecryptedConnectionForMember,
  type DecryptedSourceConnection,
  type SourceConnectionResolution,
} from './source-connections-client.js';
import { ControlPlaneTenantDirectorySource } from '../directory/ControlPlaneTenantDirectorySource.js';
import type { TenantHistoryWindow } from '../directory/TenantHistoryWindow.js';
import type { JiraWebhookLifecycleService } from './JiraWebhookLifecycleService.js';
import { S3PullCursorStore } from './S3PullCursorStore.js';
import { SingleFlight } from './SingleFlight.js';
import { boundGitHubInstallationId } from './github-installation-binding.js';
import { buildPullRunStats, type PullRunStats } from './pull-run-stats.js';

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
> & { readonly orgId?: string };

export type { PullCompleteSignal };

export type { PullFailedSignal };

export function buildPullCompleteSignal(
  message: PullDueMessage,
  completedAt: Date = new Date(),
  stats?: PullRunStats,
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
    ...(validStats(stats) ? { stats } : {}),
  };
}

function validStats(stats: PullRunStats | undefined): stats is PullRunStats {
  if (!stats) return false;
  if (pullStatsSchema.safeParse(stats).success) return true;
  logger.warn('pull_stats_dropped', { reason: 'schema_invalid' });
  return false;
}

export function buildPullFailedSignal(
  message: PullDueMessage,
  failedAt: Date,
  reason?: PullFailureReason,
): PullFailedSignal {
  const backfillLeaseToken =
    'backfillLeaseToken' in message ? message.backfillLeaseToken : undefined;
  return {
    type: 'pull-failed',
    orgId: message.tenant_id,
    sourceKind: message.kind,
    sourceId: message.sourceId,
    failedAt: failedAt.toISOString(),
    ...(backfillLeaseToken ? { backfillLeaseToken } : {}),
    ...(reason ? { reason } : {}),
  };
}

// The enclave (not the worker signal) owns the backfill horizon, so no wire message can widen how far back a pull reaches.
// One pull-due message embeds at most this many facts, so a 12-month backfill lands chunk by chunk.
export const PULL_FACT_BUDGET = 250;

export interface PullWindow {
  cursor: SyncCursor;
  options: PullOptions;
}

/** Backfill resets the cursor to re-pull from the tenant's window start; otherwise resume from it. */
export function resolvePullWindow(
  backfill: boolean,
  storedCursor: string | null,
  history: Pick<TenantHistoryWindow, 'windowFor'>,
  orgId: string,
  now: Date = new Date(),
): PullWindow {
  const since = history.windowFor(orgId, now);
  return { cursor: { value: backfill ? null : storedCursor }, options: { since, backfill } };
}

export interface PullRunnerDeps {
  s3?: S3Client;
  processedBucket?: string;
  crypto: EnclaveCrypto;
  orgId: string;
  historyWindow: Pick<TenantHistoryWindow, 'windowFor' | 'confirmBeforeBackfill'>;
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
  resourceScope: Pick<TenantResourceScope, 'read' | 'transitionBackfill'>;
  signal?: AbortSignal;
}

export type PullRunResult =
  | {
      outcome: 'processed';
      facts: ProcessedFact[];
      cursor: string | null;
      hasMore: boolean;
      stats: PullRunStats;
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
        | 'control_plane_spki_pin_mismatch'
        | 'connection_response_invalid'
        | 'connection_integrity_failed'
        | 'connection_decrypt_failed'
        | 'resource_scope_unavailable';
      sourceId: string;
      sourceKind: string;
    }
  | {
      outcome: 'superseded';
      sourceId: string;
      sourceKind: string;
    }
  | {
      outcome: 'paused';
      sourceId: string;
      sourceKind: string;
    };

export type PullNotProcessedReason = Extract<PullRunResult, { outcome: 'not_processed' }>['reason'];

const consoleLogger: Logger = logger;

// Every cursor is sealed in S3: a member's is a personal sync token and a spec connector's is an envelope.
async function loadSealedCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
): Promise<string | null> {
  return sealedCursorStore(deps, message).load(message.sourceId);
}

async function saveSealedCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
  value: string | null,
): Promise<void> {
  await sealedCursorStore(deps, message).save(message.sourceId, value);
}

// A source that is neither member nor Notion has its own failure code from the two that name those.
function isGenericSealedSource(message: PullDueMessage): boolean {
  return message.ownerAccountId === undefined && message.kind !== NOTION_KIND;
}

function sealedCursorStore(deps: PullRunnerDeps, message: PullDueMessage): S3PullCursorStore {
  if (!deps.s3 || !deps.processedBucket) {
    if (isGenericSealedSource(message)) throw new Error('pull_cursor_store_unavailable');
    throw new Error('member_pull_cursor_store_unavailable');
  }
  return new S3PullCursorStore({
    s3: deps.s3,
    crypto: deps.crypto,
    bucket: deps.processedBucket,
    orgId: deps.orgId,
    deploymentId: deps.deploymentId,
  });
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

// The control plane's projection is only a claim; the mint uses the installation sealed at connect.
function sealedInstallationId(
  connection: Pick<DecryptedSourceConnection, 'accessToken' | 'installationId'>,
): string | undefined {
  if (!connection.installationId) return undefined;
  return boundGitHubInstallationId(connection.accessToken, connection.installationId);
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
  if (kind !== 'github') return connection.accessToken;
  if (!connection.connectionId || !connection.activationGeneration) {
    throw new Error('github_connection_binding_missing');
  }
  const minted = await mintGitHubInstallationTokenForPull(
    sealedInstallationId(connection),
    mintGitHubInstallationToken,
    {
      orgId: scope.orgId,
      connectionId: connection.connectionId,
      connectionGeneration: connection.activationGeneration,
    },
  );
  if (minted.outcome === 'rate_limited') {
    throw new Error('github_mint_rate_limited');
  }
  return minted.accessToken;
}

export type PullConnectorBuilder = (
  kind: string,
  token: string,
  connectionMetadata: PullConnectionMetadata,
) => Connector | null;

// Every client here MUST egress via the proxy — either the global undici dispatcher
// (fetch-based SDKs) or an explicit agent (axios/node:http SDKs like Slack), else its
// pull dials the internet directly and fails closed on real hardware.
export function buildConnector(
  kind: string,
  token: string,
  connectionMetadata?: PullConnectionMetadata,
): Connector | null {
  const deps: PullConnectorDeps = {
    logger: consoleLogger,
    token,
    ...(connectionMetadata?.externalTenantId
      ? { externalTenantId: connectionMetadata.externalTenantId }
      : {}),
    httpsProxyAgent: externalHttpsProxyAgent(),
    ...(isSpecConnectorKind(kind) && connectionMetadata?.orgId
      ? {
          connectorTransport: new ConnectorEgressTransport({
            kind,
            orgId: connectionMetadata.orgId,
            token,
            logger: consoleLogger,
          }),
        }
      : {}),
  };
  return createPullConnector(kind, deps);
}

/** Handles a single content-free `pull-due` signal end to end, in-enclave. */
export async function runPull(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connectorBuilder: PullConnectorBuilder = buildConnector,
): Promise<PullRunResult> {
  const routing = resolvePullRouting(message, deps.orgId);
  if (routing === null) return notProcessed(message, 'routing_invalid');
  const memberScope = routing.memberScope;
  const scope = await readResourceScope(deps, message, memberScope);
  if (scope === RESOURCE_SCOPE_UNAVAILABLE) {
    return notProcessed(message, 'resource_scope_unavailable');
  }
  if (scope?.paused) return pausedPull(message);
  const resolved = await resolveSourceConnection(message, deps, memberScope);
  if (resolved.outcome === 'not_processed') {
    return notProcessed(message, resolved.reason);
  }
  if (resolved.outcome === 'missing') {
    if (message.trigger === 'activation') return superseded(message);
    return notProcessed(message, 'connection_missing');
  }
  const connection = resolved.connection;
  if (
    message.trigger === 'activation' &&
    message.activationGeneration !== connection.activationGeneration
  ) {
    return superseded(message);
  }

  const startedAt = Date.now();
  const sealedCursor = await loadRunCursor(deps, message);

  const token = await resolveSourceToken(
    message.kind,
    connection,
    deps.mintGitHubInstallationToken,
    { orgId: deps.orgId },
  );
  if (!token) {
    return notProcessed(message, 'token_missing');
  }
  const connector = buildPullConnector(connectorBuilder, message.kind, token, {
    ...connectionMetadata(connection),
    orgId: deps.orgId,
  });
  if (!connector) {
    return notProcessed(message, 'connector_missing');
  }

  const backfill = message.backfill || scope?.backfill === 'owed';
  if (backfill)
    await deps.historyWindow.confirmBeforeBackfill(deps.orgId, () => directorySource(deps));
  const window = scopedWindow(
    budgetedWindow(
      resolvePullWindow(
        backfill,
        backfill ? null : await resumeCursor(deps, message, sealedCursor),
        deps.historyWindow,
        deps.orgId,
      ),
    ),
    scope,
  );
  const result = await pullWithRefresh(
    message,
    deps,
    connection,
    connector,
    window,
    connectorBuilder,
    memberScope,
  );

  const cursor = result.cursor.value;
  await reconcileJiraWebhook(message, deps, result.connection);
  const admission = scope ? admissionOf(scope) : ADMIT_ALL;
  const facts = await handlePulledFacts(deps, message.kind, result, { memberScope, admission });
  // A connector that claims more without moving its cursor would loop, so only progress counts.
  const hasMore = result.hasMore && !result.earlyReturn && cursor !== window.cursor.value;
  return {
    outcome: 'processed',
    facts,
    cursor,
    hasMore,
    stats: buildPullRunStats({
      pulled: result.facts,
      admitted: result.facts.filter((fact) => admission(fact.resourceExternalId)),
      processed: facts,
      connectorStats: result.stats,
      durationMs: Date.now() - startedAt,
      hasMore,
      backfill,
    }),
    sourceId: message.sourceId,
    sourceKind: message.kind,
    persistCursor: async () => {
      await saveSealedCursor(deps, message, cursor);
      await settleBackfill(deps, message.kind, scope, hasMore);
    },
  };
}

const RESOURCE_SCOPE_UNAVAILABLE = 'unavailable';

// The runner's own read is the one snapshot: the pipeline never reads the scope again for a pull.
function handlePulledFacts(
  deps: PullRunnerDeps,
  kind: string,
  pulled: Pick<PullResult, 'facts' | 'containers'>,
  scope: { memberScope: MemberPullScope | undefined; admission: ResourceAdmission },
): Promise<ProcessedFact[]> {
  const { facts, containers } = pulled;
  if (scope.memberScope) {
    return deps.pipeline.handlePulled(
      facts,
      containers,
      kind,
      ADMIT_ALL,
      deps.signal,
      scope.memberScope,
    );
  }
  return deps.pipeline.handlePulled(facts, containers, kind, scope.admission, deps.signal);
}

// Idle by design and neither done nor failed: the cursor and any lease stay as they are, so a resume continues from there.
function pausedPull(message: PullDueMessage): PullRunResult {
  return { outcome: 'paused', sourceId: message.sourceId, sourceKind: message.kind };
}

// Only a definitive "never configured" reads as everything; a missing reader or any other failure stops the pull before the cursor can move.
async function readResourceScope(
  deps: PullRunnerDeps,
  message: PullDueMessage,
  memberScope: MemberPullScope | undefined,
): Promise<ResourceScope | undefined | typeof RESOURCE_SCOPE_UNAVAILABLE> {
  if (memberScope || !isPausableSourceKind(message.kind)) return undefined;
  if (!deps.resourceScope) return RESOURCE_SCOPE_UNAVAILABLE;
  try {
    return await deps.resourceScope.read(message.kind);
  } catch {
    return RESOURCE_SCOPE_UNAVAILABLE;
  }
}

function scopedWindow(window: PullWindow, scope: ResourceScope | undefined): PullWindow {
  if (scope?.mode !== 'selected') return window;
  const selected = new Set(scope.resourceIds);
  return {
    cursor: window.cursor,
    options: { ...window.options, includesResource: (id) => selected.has(id) },
  };
}

function directorySource(deps: PullRunnerDeps): ControlPlaneTenantDirectorySource {
  return new ControlPlaneTenantDirectorySource({
    controlPlaneUrl: deps.controlPlaneUrl,
    runtimeDeploymentId: deps.runtimeDeploymentId ?? deps.deploymentId,
    tenantDeploymentId: deps.deploymentId,
    orgId: deps.orgId,
    agentToken: () => deps.agentToken,
    fetchImpl: deps.controlPlaneFetch,
  });
}

// Runs after the cursor is durable, so a state that moved always has a cursor that matches it.
async function settleBackfill(
  deps: PullRunnerDeps,
  sourceKind: string,
  scope: ResourceScope | undefined,
  hasMore: boolean,
): Promise<void> {
  if (!scope || scope.backfill === 'none') return;
  const base = { sourceKind, expectedRevision: scope.revision };
  try {
    if (scope.backfill === 'owed') {
      await deps.resourceScope.transitionBackfill({ ...base, from: 'owed', to: 'running' });
    }
    if (!hasMore) {
      await deps.resourceScope.transitionBackfill({ ...base, from: 'running', to: 'none' });
    }
  } catch (error) {
    if (!(error instanceof ResourceScopeConflictError)) throw error;
  }
}

async function loadRunCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
): Promise<string | null> {
  if (message.kind === NOTION_KIND) return null;
  return loadSealedCursor(deps, message);
}

async function resumeCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
  sealedCursor: string | null,
): Promise<string | null> {
  if (message.kind === NOTION_KIND) return loadNotionCursor(deps, message);
  return sealedCursor;
}

// An unreadable sealed Notion cursor fails the pull rather than silently starting a fresh window; an absent one starts fresh.
// An empty object is a marker an earlier release wrote when there was nothing to resume, and reads as no cursor.
async function loadNotionCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
): Promise<string | null> {
  const sealed = await sealedCursorStore(deps, message).loadStrict(message.sourceId);
  if (!sealed.found || sealed.value === '') return null;
  return sealed.value;
}

interface PullRouting {
  memberScope?: MemberPullScope;
}

// A personal kind routes only with its owner, an owner only with a personal kind, each under its derived source id.
function resolvePullRouting(message: PullDueMessage, orgId: string): PullRouting | null {
  if (message.tenant_id !== orgId) return null;
  const ownerAccountId = message.ownerAccountId;
  const perPerson = supportsPerPersonMode(message.kind);
  if (ownerAccountId === undefined) {
    if (perPerson) return null;
    return message.sourceId === deriveSourceId(orgId, message.kind) ? {} : null;
  }
  if (!perPerson) return null;
  let memberSourceId: string;
  try {
    memberSourceId = deriveMemberSourceId(orgId, message.kind, ownerAccountId);
  } catch {
    return null;
  }
  return message.sourceId === memberSourceId ? { memberScope: { ownerAccountId } } : null;
}

function resolveSourceConnection(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  memberScope: MemberPullScope | undefined,
): Promise<SourceConnectionResolution> {
  if (memberScope) {
    return getDecryptedConnectionForMember(
      {
        controlPlaneUrl: deps.controlPlaneUrl,
        runtimeDeploymentId: deps.runtimeDeploymentId ?? deps.deploymentId,
        tenantDeploymentId: deps.deploymentId,
        agentToken: deps.agentToken,
        orgId: deps.orgId,
        kind: message.kind,
        ownerAccountId: memberScope.ownerAccountId,
      },
      deps.crypto,
      deps.controlPlaneFetch,
    );
  }
  return getDecryptedConnectionForKind(
    deps.controlPlaneUrl,
    deps.runtimeDeploymentId ?? deps.deploymentId,
    deps.deploymentId,
    deps.agentToken,
    message.kind,
    deps.orgId,
    deps.crypto,
    deps.controlPlaneFetch,
  );
}

function budgetedWindow(window: PullWindow): PullWindow {
  return { cursor: window.cursor, options: { ...window.options, maxFacts: PULL_FACT_BUDGET } };
}

function buildPullConnector(
  connectorBuilder: PullConnectorBuilder,
  kind: string,
  token: string,
  connectionMetadata: PullConnectionMetadata,
): Connector | null {
  return connectorBuilder(kind, token, connectionMetadata);
}

function superseded(message: PullDueMessage): PullRunResult {
  return { outcome: 'superseded', sourceId: message.sourceId, sourceKind: message.kind };
}

function notProcessed(message: PullDueMessage, reason: PullNotProcessedReason): PullRunResult {
  return { outcome: 'not_processed', reason, sourceId: message.sourceId, sourceKind: message.kind };
}

export interface UnauthorizedRefresh {
  sourceKind: string;
  connection: DecryptedSourceConnection;
  originalError: unknown;
  deps: Pick<
    PullRunnerDeps,
    'orgId' | 'deploymentId' | 'refreshOAuthCredential' | 'mintGitHubInstallationToken'
  >;
  ownerAccountId?: string;
  reconnect(): Promise<SourceConnectionResolution>;
  build(token: string, connection: DecryptedSourceConnection): Connector | null;
}

export type RefreshedConnector =
  | { outcome: 'ready'; connector: Connector; connection: DecryptedSourceConnection }
  | { outcome: 'rate_limited' };

/** One recovery for a 401; a non-success refresh throws OAuthRefreshFailedError caused by the original, other failures rethrow it. */
export async function refreshConnectorAfterUnauthorized(
  input: UnauthorizedRefresh,
): Promise<RefreshedConnector> {
  if (input.connection.kind === 'github') {
    return remintGitHubConnector(input);
  }
  return refreshOAuthConnector(input);
}

export async function pullWithRefresh(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connection: DecryptedSourceConnection,
  connector: Connector,
  window: PullWindow,
  connectorBuilder: PullConnectorBuilder = buildConnector,
  memberScope?: MemberPullScope,
) {
  try {
    return {
      ...(await connector.pull(window.cursor, window.options)),
      connection,
    };
  } catch (error) {
    if (!isUnauthorized(error)) throw error;
    const fresh = await refreshConnectorAfterUnauthorized({
      sourceKind: message.kind,
      connection,
      originalError: error,
      deps,
      ...(memberScope === undefined ? {} : { ownerAccountId: memberScope.ownerAccountId }),
      reconnect: () => resolveSourceConnection(message, deps, memberScope),
      build: (token, fresher) =>
        buildPullConnector(connectorBuilder, message.kind, token, {
          ...connectionMetadata(fresher),
          orgId: deps.orgId,
        }),
    });
    if (fresh.outcome === 'rate_limited') return rateLimitedRetry();
    return {
      ...(await fresh.connector.pull(window.cursor, window.options)),
      connection: fresh.connection,
    };
  }
}

// A throttled re-mint fails the pull loudly, like a throttled first mint.
function rateLimitedRetry(): never {
  throw new Error('github_mint_rate_limited');
}

// A github pull has no refresh token: re-mint the ~1h install token and retry once.
// The retry mint bypasses the TTL cache — recovery is always a fresh mint.
async function remintGitHubConnector(input: UnauthorizedRefresh): Promise<RefreshedConnector> {
  const { deps, connection, originalError } = input;
  if (!deps.mintGitHubInstallationToken || !connection.installationId) throw originalError;
  const minted = await mintGitHubInstallationTokenForPull(
    sealedInstallationId(connection),
    deps.mintGitHubInstallationToken,
    {
      orgId: deps.orgId,
      connectionId: connection.connectionId,
      connectionGeneration: connection.activationGeneration,
    },
    { bypassCache: true },
  );
  if (minted.outcome === 'rate_limited') return { outcome: 'rate_limited' };
  const connector = input.build(minted.accessToken, connection);
  if (!connector) throw originalError;
  return { outcome: 'ready', connector, connection };
}

async function refreshOAuthConnector(input: UnauthorizedRefresh): Promise<RefreshedConnector> {
  const { deps, connection, originalError } = input;
  const refreshCredential = deps.refreshOAuthCredential;
  if (!refreshCredential) throw originalError;
  if (!connection.encryptedRefreshToken || !connection.refreshCiphertextSha256) {
    throw originalError;
  }
  const flight = await oauthRefreshFlights.run(`${deps.orgId}:${connection.connectionId}`, () =>
    rotateOrAdoptOAuthConnection(input, refreshCredential),
  );
  if ('failed' in flight) throw new OAuthRefreshFailedError(flight.failed, originalError);
  const refreshed = flight.connection;
  if (!refreshed || refreshed.activationGeneration !== connection.activationGeneration) {
    throw originalError;
  }
  const token = await resolveSourceToken(input.sourceKind, refreshed, undefined, {
    orgId: deps.orgId,
  });
  if (!token) throw originalError;
  const connector = input.build(token, refreshed);
  if (!connector) throw originalError;
  return { outcome: 'ready', connector, connection: refreshed };
}

type OAuthRefreshFlightResult =
  | { connection: DecryptedSourceConnection | null }
  | { failed: FailedOAuthRefreshOutcome };

// A rotating refresh token is single-use, so a second refresh from a stale snapshot would revoke the first one's result.
// The flight resolves a failure instead of throwing so each waiting caller wraps its own 401 as the cause.
const oauthRefreshFlights = new SingleFlight<OAuthRefreshFlightResult>();

async function rotateOrAdoptOAuthConnection(
  input: UnauthorizedRefresh,
  refreshOAuthCredential: NonNullable<PullRunnerDeps['refreshOAuthCredential']>,
): Promise<OAuthRefreshFlightResult> {
  const { deps, connection } = input;
  const rotated = await rotatedConnectionSince(input);
  if (rotated) return { connection: rotated };
  const command = oauthRefreshCommandSchema.parse({
    encryptedRefreshToken: connection.encryptedRefreshToken,
    orgId: deps.orgId,
    deploymentId: deps.deploymentId,
    sourceKind: input.sourceKind,
    connectionId: connection.connectionId,
    activationGeneration: connection.activationGeneration,
    attestationGeneration: connection.attestationGeneration,
    attemptId: randomBytes(32).toString('hex'),
    expectedRefreshCiphertextSha256: connection.refreshCiphertextSha256,
    ...(input.ownerAccountId === undefined ? {} : { ownerAccountId: input.ownerAccountId }),
  });
  let outcome: OAuthRefreshMetadataUpdate['outcome'];
  try {
    outcome = (await refreshOAuthCredential(command)).outcome;
  } catch {
    return { connection: null };
  }
  if (outcome !== 'success') return { failed: outcome };
  const resolution = await input.reconnect();
  return { connection: resolution.outcome === 'connected' ? resolution.connection : null };
}

async function rotatedConnectionSince(
  input: UnauthorizedRefresh,
): Promise<DecryptedSourceConnection | null> {
  try {
    const current = await input.reconnect();
    const rotated =
      current.outcome === 'connected' &&
      current.connection.refreshCiphertextSha256 !== input.connection.refreshCiphertextSha256;
    return rotated ? current.connection : null;
  } catch {
    return null;
  }
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

export function connectionMetadata(connection: DecryptedSourceConnection): PullConnectionMetadata {
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

export function isUnauthorized(error: unknown, seen = new Set<object>()): boolean {
  if (typeof error !== 'object' || error === null) return false;
  if (seen.has(error)) return false;
  seen.add(error);
  const value = error as Record<string, unknown>;
  if (value['status'] === 401 || value['statusCode'] === 401 || value['httpStatus'] === 401) {
    return true;
  }
  return isUnauthorized(value['cause'], seen);
}
