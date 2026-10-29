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
  type DocumentBodyMode,
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
import { externalHttpsProxyAgent } from '../egress/proxy.js';
import { ProviderRejectedError } from '../egress/provider-token-fetch.js';
import { deriveMemberSourceId, deriveSourceId } from '@folklore/utils';
import { logger } from '../logger.js';
import type { MemberPullScope, Pipeline, ProcessedFact } from '../pipeline/index.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { GitHubCodebaseConnectionResolver } from '../codebase/GitHubCodebaseConnectionResolver.js';
import type { CodebaseSelectionStore } from '../codebase/CodebaseSelectionStore.js';
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
import type { JiraWebhookLifecycleService } from './JiraWebhookLifecycleService.js';
import {
  BODY_GATED_KINDS,
  DOCUMENT_BODY_RELEASE,
  documentBodyModeFor,
} from './document-body-release.js';
import type { ExportedPageRefReaderPort } from './ExportedPageRefReader.js';
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
>;

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

// the enclave (not the worker signal) owns the uniform 12-month backfill horizon,
// so no wire message can widen how far back a pull reaches.
const BACKFILL_WINDOW_MONTHS = 12;
// One pull-due message embeds at most this many facts, so a 12-month backfill lands chunk by chunk.
export const PULL_FACT_BUDGET = 250;

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
  return { cursor: { value: backfill ? null : storedCursor }, options: { since, backfill } };
}

export type PullCursorStoreMode = 'sealed' | 'legacy_ssm';

export interface PullRunnerDeps {
  ssm: SSMClient;
  /** Where every cursor lives; absent keeps `code`, member and Notion cursors sealed and the rest in SSM. */
  cursorStore?: PullCursorStoreMode;
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
  resourceScope: Pick<TenantResourceScope, 'read' | 'transitionBackfill'>;
  exportedPageRefs?: ExportedPageRefReaderPort;
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
        | 'export_refs_unavailable'
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
      outcome: 'declined';
      reason: 'body_release_off';
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

// `code` cursors outgrow SSM and hold file paths, member cursors are personal sync tokens; both stay sealed in S3.
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

const SSM_ACCESS_DENIED = 'AccessDeniedException';

function isSealedMode(deps: PullRunnerDeps): boolean {
  return deps.cursorStore === 'sealed';
}

// Only sealed mode names a source that is neither code, member nor Notion; every other mode keeps today's two codes.
function isGenericSealedSource(deps: PullRunnerDeps, message: PullDueMessage): boolean {
  return isSealedMode(deps) && message.ownerAccountId === undefined && message.kind !== NOTION_KIND;
}

// An unreadable sealed cursor re-snapshots; a missing one is read forward once from the legacy SSM parameter.
async function loadCursorForRun(
  deps: PullRunnerDeps,
  message: PullDueMessage,
): Promise<string | null> {
  const sealed = await sealedCursorStore(deps, message).loadState(message.sourceId);
  if (sealed.state === 'present') return sealed.value;
  if (sealed.state === 'unreadable') return null;
  try {
    return await loadCursor(deps.ssm, message.tenant_id, message.sourceId);
  } catch (error) {
    if ((error as { name?: unknown } | null)?.name === SSM_ACCESS_DENIED) return null;
    throw error;
  }
}

function sealedCursorStore(deps: PullRunnerDeps, message: PullDueMessage): S3PullCursorStore {
  if (!deps.s3 || !deps.processedBucket) {
    if (message.kind === 'code') throw new Error('code_pull_cursor_store_unavailable');
    if (isGenericSealedSource(deps, message)) throw new Error('pull_cursor_store_unavailable');
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
  if (kind !== 'github' && kind !== 'code') return connection.accessToken;
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
    // github stays loud (DLQ alarm); a `code` mint-403 is a non-throwing early return the
    // runner turns into a cursor tick bump (scheduler cadence is fixed, no backoff to rely on).
    if (kind === 'code') return null;
    throw new Error('github_mint_rate_limited');
  }
  return minted.accessToken;
}

export interface PullBodyPolicy {
  documentBodies: DocumentBodyMode;
  exportedPageIds?: ReadonlySet<string>;
}

export type PullConnectorBuilder = (
  kind: string,
  token: string,
  connectionMetadata: PullConnectionMetadata,
  codebaseSelection?: CodebaseRepositorySelection,
  bodyPolicy?: PullBodyPolicy,
) => Connector | null;

// Every client here MUST egress via the proxy — either the global undici dispatcher
// (fetch-based SDKs) or an explicit agent (axios/node:http SDKs like Slack), else its
// pull dials the internet directly and fails closed on real hardware.
export function buildConnector(
  kind: string,
  token: string,
  connectionMetadata?: PullConnectionMetadata,
  codebaseSelection?: CodebaseRepositorySelection,
  bodyPolicy?: PullBodyPolicy,
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
    ...(bodyPolicy ? { documentBodies: bodyPolicy.documentBodies } : {}),
    ...(bodyPolicy?.exportedPageIds ? { exportedPageIds: bodyPolicy.exportedPageIds } : {}),
  };
  return createPullConnector(kind, deps);
}

/** Handles a single content-free `pull-due` signal end to end, in-enclave. */
export async function runPull(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connectorBuilder: PullConnectorBuilder = buildConnector,
  release: ReadonlyMap<string, DocumentBodyMode> = DOCUMENT_BODY_RELEASE,
): Promise<PullRunResult> {
  const routing = resolvePullRouting(message, deps.orgId);
  if (routing === null) return notProcessed(message, 'routing_invalid');
  const mode = documentBodyModeFor(message.kind, release);
  const memberScope = routing.memberScope;
  if (mode === 'off' && !memberScope && BODY_GATED_KINDS.has(message.kind)) {
    return declined(message);
  }
  const scope = await readResourceScope(deps, message, memberScope);
  if (scope === RESOURCE_SCOPE_UNAVAILABLE) {
    return notProcessed(message, 'resource_scope_unavailable');
  }
  if (scope?.paused) return pausedPull(message);
  const resolved =
    message.kind === 'code'
      ? await resolveCodebaseConnection(deps)
      : await resolveSourceConnection(message, deps, memberScope);
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

  const startedAt = Date.now();
  const isCode = message.kind === 'code';
  const usesSealedCursor =
    isCode || memberScope !== undefined || message.kind === NOTION_KIND || isSealedMode(deps);
  // The code cursor loads BEFORE the mint so a mint-403 early return can bump its tick.
  const sealedCursor = await loadRunCursor(deps, message, { isCode, memberScope });

  const token = await resolveSourceToken(
    message.kind,
    connection,
    deps.mintGitHubInstallationToken,
    { orgId: deps.orgId },
  );
  if (!token) {
    return notProcessed(message, 'token_missing');
  }
  const exportedPageIds = await loadExportedPageIds(message.kind, mode, deps);
  if (exportedPageIds === EXPORT_REFS_UNAVAILABLE) {
    return notProcessed(message, 'export_refs_unavailable');
  }
  const bodyPolicy = pullBodyPolicy(mode, exportedPageIds);
  const connector = buildPullConnector(
    connectorBuilder,
    message.kind,
    token,
    connectionMetadata(connection),
    codebaseSelection,
    bodyPolicy,
  );
  if (!connector) {
    return notProcessed(message, 'connector_missing');
  }

  const backfill = message.backfill || scope?.backfill === 'owed';
  const window = scopedWindow(
    budgetedWindow(
      resolvePullWindow(
        backfill,
        backfill ? null : await resumeCursor(deps, message, usesSealedCursor, sealedCursor),
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
    codebaseSelection,
    memberScope,
    bodyPolicy,
  );

  const cursor =
    result.earlyReturn && isCode ? advanceCodeCursorTick(result.cursor.value) : result.cursor.value;
  await reconcileJiraWebhook(message, deps, result.connection);
  const admission = scope ? admissionOf(scope) : ADMIT_ALL;
  const facts = await handlePulledFacts(deps, message.kind, result, { memberScope, admission });
  // A connector that claims more without moving its cursor would loop, so only progress counts.
  const hasMore =
    result.hasMore && !result.earlyReturn && cursorProgressed(isCode, window.cursor.value, cursor);
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
      await persistRunCursor(deps, message, usesSealedCursor, cursor);
      await settleBackfill(deps, message.kind, scope, hasMore);
    },
  };
}

async function persistRunCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
  usesSealedCursor: boolean,
  cursor: string | null,
): Promise<void> {
  if (usesSealedCursor) {
    await saveSealedCursor(deps, message, message.kind === NOTION_KIND ? (cursor ?? '') : cursor);
    return;
  }
  await saveCursor(deps.ssm, message.tenant_id, message.sourceId, cursor);
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
  scope: { isCode: boolean; memberScope: MemberPullScope | undefined },
): Promise<string | null> {
  if (message.kind === NOTION_KIND) return null;
  if (scope.isCode || scope.memberScope !== undefined) return loadSealedCursor(deps, message);
  return isSealedMode(deps) ? loadCursorForRun(deps, message) : null;
}

function cursorProgressed(isCode: boolean, previous: string | null, next: string | null): boolean {
  return isCode ? code.codeCursorProgressed(previous, next) : next !== previous;
}

async function resumeCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
  usesSealedCursor: boolean,
  sealedCursor: string | null,
): Promise<string | null> {
  if (message.kind === NOTION_KIND) return loadNotionCursor(deps, message);
  if (!usesSealedCursor) return loadCursor(deps.ssm, message.tenant_id, message.sourceId);
  return sealedCursor;
}

// Notion moved from SSM to the sealed store: SSM is read only while no sealed object exists, and an unreadable one fails the pull rather than re-pulling from the legacy value.
async function loadNotionCursor(
  deps: PullRunnerDeps,
  message: PullDueMessage,
): Promise<string | null> {
  const sealed = await sealedCursorStore(deps, message).loadStrict(message.sourceId);
  if (sealed.found) return sealed.value === '' ? null : sealed.value;
  return loadCursor(deps.ssm, message.tenant_id, message.sourceId);
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

const EXPORT_REFS_UNAVAILABLE = 'unavailable';

// Only a mode that reads bodies must fail closed: off keeps today's title-only pull, which the database never blocked.
async function loadExportedPageIds(
  kind: string,
  mode: DocumentBodyMode,
  deps: PullRunnerDeps,
): Promise<ReadonlySet<string> | undefined | typeof EXPORT_REFS_UNAVAILABLE> {
  if (kind !== NOTION_KIND) return undefined;
  const ids = await readExportedPageIds(deps);
  if (ids !== undefined) return ids;
  return mode === 'off' ? undefined : EXPORT_REFS_UNAVAILABLE;
}

async function readExportedPageIds(deps: PullRunnerDeps): Promise<ReadonlySet<string> | undefined> {
  if (!deps.exportedPageRefs) return undefined;
  try {
    const ids = await deps.exportedPageRefs.notionPageIds(deps.orgId);
    return ids === 'database_unavailable' ? undefined : ids;
  } catch {
    return undefined;
  }
}

function pullBodyPolicy(
  mode: DocumentBodyMode,
  exportedPageIds: ReadonlySet<string> | undefined,
): PullBodyPolicy | undefined {
  if (mode === 'off' && exportedPageIds === undefined) return undefined;
  return { documentBodies: mode, ...(exportedPageIds ? { exportedPageIds } : {}) };
}

function buildPullConnector(
  connectorBuilder: PullConnectorBuilder,
  kind: string,
  token: string,
  connectionMetadata: PullConnectionMetadata,
  codebaseSelection?: CodebaseRepositorySelection,
  bodyPolicy?: PullBodyPolicy,
): Connector | null {
  if (bodyPolicy) {
    return connectorBuilder(kind, token, connectionMetadata, codebaseSelection, bodyPolicy);
  }
  if (codebaseSelection) {
    return connectorBuilder(kind, token, connectionMetadata, codebaseSelection);
  }
  return connectorBuilder(kind, token, connectionMetadata);
}

function superseded(message: PullDueMessage): PullRunResult {
  return { outcome: 'superseded', sourceId: message.sourceId, sourceKind: message.kind };
}

function declined(message: PullDueMessage): PullRunResult {
  return {
    outcome: 'declined',
    reason: 'body_release_off',
    sourceId: message.sourceId,
    sourceKind: message.kind,
  };
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

/** One recovery for a 401, shared by pulls and live listings; every failure rethrows the original error. */
export async function refreshConnectorAfterUnauthorized(
  input: UnauthorizedRefresh,
): Promise<RefreshedConnector> {
  if (input.connection.kind === 'github' || input.connection.kind === 'code') {
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
  codebaseSelection?: CodebaseRepositorySelection,
  memberScope?: MemberPullScope,
  bodyPolicy?: PullBodyPolicy,
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
        buildPullConnector(
          connectorBuilder,
          message.kind,
          token,
          connectionMetadata(fresher),
          codebaseSelection,
          bodyPolicy,
        ),
    });
    if (fresh.outcome === 'rate_limited') return rateLimitedRetry(message.kind, window, connection);
    return {
      ...(await fresh.connector.pull(window.cursor, window.options)),
      connection: fresh.connection,
    };
  }
}

// A code pull has no backoff of its own, so a throttled re-mint ends the attempt and the tick moves on.
function rateLimitedRetry(
  sourceKind: string,
  window: PullWindow,
  connection: DecryptedSourceConnection,
): PullResult & { connection: DecryptedSourceConnection } {
  if (sourceKind !== 'code') throw new Error('github_mint_rate_limited');
  return {
    facts: [],
    containers: [],
    cursor: window.cursor,
    hasMore: false,
    earlyReturn: true,
    connection,
  };
}

// A github/code pull has no refresh token: re-mint the ~1h install token and retry once.
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
  const refreshed = await oauthRefreshFlights.run(`${deps.orgId}:${connection.connectionId}`, () =>
    rotateOrAdoptOAuthConnection(input, refreshCredential),
  );
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

// A rotating refresh token is single-use, so a second refresh from a stale snapshot would revoke the first one's result.
const oauthRefreshFlights = new SingleFlight<DecryptedSourceConnection | null>();

async function rotateOrAdoptOAuthConnection(
  input: UnauthorizedRefresh,
  refreshOAuthCredential: NonNullable<PullRunnerDeps['refreshOAuthCredential']>,
): Promise<DecryptedSourceConnection | null> {
  const { deps, connection } = input;
  const rotated = await rotatedConnectionSince(input);
  if (rotated) return rotated;
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
  try {
    const refresh = await refreshOAuthCredential(command);
    if (refresh.outcome !== 'success') return null;
  } catch {
    return null;
  }
  const resolution = await input.reconnect();
  return resolution.outcome === 'connected' ? resolution.connection : null;
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
