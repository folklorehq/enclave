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
  type SyncCursor,
} from '@folklore/connectors';
import { NOTION_KIND, supportsPerPersonMode } from '@folklore/contracts';
import {
  oauthRefreshCommandSchema,
  type OAuthRefreshCommand,
  type OAuthRefreshMetadataUpdate,
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
import { boundGitHubInstallationId } from './github-installation-binding.js';

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

export type { PullFailedSignal };

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
  exportedPageRefs?: ExportedPageRefReaderPort;
  signal?: AbortSignal;
}

export type PullRunResult =
  | {
      outcome: 'processed';
      facts: ProcessedFact[];
      cursor: string | null;
      hasMore: boolean;
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
        | 'connection_decrypt_failed'
        | 'export_refs_unavailable';
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

function sealedCursorStore(deps: PullRunnerDeps, message: PullDueMessage): S3PullCursorStore {
  if (!deps.s3 || !deps.processedBucket) {
    if (message.kind === 'code') throw new Error('code_pull_cursor_store_unavailable');
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

  const isCode = message.kind === 'code';
  const usesSealedCursor = isCode || memberScope !== undefined;
  // The code cursor loads BEFORE the mint so a mint-403 early return can bump its tick.
  const storedCursor = usesSealedCursor ? await loadSealedCursor(deps, message) : null;

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

  const window = budgetedWindow(
    resolvePullWindow(
      message.backfill,
      usesSealedCursor
        ? storedCursor
        : await loadCursor(deps.ssm, message.tenant_id, message.sourceId),
    ),
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

  const cursor = result.earlyReturn
    ? advanceCodeCursorTick(result.cursor.value)
    : result.cursor.value;
  await reconcileJiraWebhook(message, deps, result.connection);
  const facts = memberScope
    ? await deps.pipeline.handlePulled(
        result.facts,
        result.containers,
        message.kind,
        deps.signal,
        memberScope,
      )
    : await deps.pipeline.handlePulled(result.facts, result.containers, message.kind, deps.signal);
  return {
    outcome: 'processed',
    facts,
    cursor,
    // A connector that claims more without moving its cursor would loop, so only progress counts.
    hasMore: result.hasMore && !result.earlyReturn && cursor !== window.cursor.value,
    sourceId: message.sourceId,
    sourceKind: message.kind,
    persistCursor: async () => {
      if (usesSealedCursor) {
        await saveSealedCursor(deps, message, cursor);
        return;
      }
      await saveCursor(deps.ssm, message.tenant_id, message.sourceId, cursor);
    },
  };
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
    if (connection.kind === 'github' || connection.kind === 'code') {
      return retryPullWithFreshGitHubToken(
        deps,
        message.kind,
        connection,
        window,
        connectorBuilder,
        error,
        codebaseSelection,
        bodyPolicy,
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
      ...(memberScope === undefined ? {} : { ownerAccountId: memberScope.ownerAccountId }),
    });
    try {
      const refresh = await deps.refreshOAuthCredential(command);
      if (refresh.outcome !== 'success') throw error;
    } catch {
      throw error;
    }
    const refreshedResolution = await resolveSourceConnection(message, deps, memberScope);
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
      bodyPolicy,
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
  connectorBuilder: PullConnectorBuilder,
  originalError: unknown,
  codebaseSelection?: CodebaseRepositorySelection,
  bodyPolicy?: PullBodyPolicy,
) {
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
    bodyPolicy,
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
