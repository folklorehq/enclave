/** Drives one connector pull() pass entirely inside the enclave — plaintext never leaves the enclave. */
import { randomBytes } from 'node:crypto';
import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import type { S3Client } from '@aws-sdk/client-s3';
import type { Logger } from '@folklore/core';
import {
  code,
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
import { logger } from '../logger.js';
import type { Pipeline, ProcessedFact } from '../pipeline/index.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  getDecryptedConnectionForKind,
  type DecryptedSourceConnection,
} from './source-connections-client.js';
import { S3PullCursorStore } from './S3PullCursorStore.js';

export type { PullDueMessage };

// Content-free completion signal the worker uses to advance sync health; the
// enclave has no DB access, so this is how last_successful_sync_at gets written worker-side.
export interface PullCompleteSignal {
  type: 'pull-complete';
  orgId: string;
  sourceKind: string;
  sourceId: string;
  completedAt: string;
}

export function buildPullCompleteSignal(
  message: PullDueMessage,
  completedAt: Date = new Date(),
): PullCompleteSignal {
  return {
    type: 'pull-complete',
    orgId: message.tenant_id,
    sourceKind: message.kind,
    sourceId: message.sourceId,
    completedAt: completedAt.toISOString(),
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
  deploymentId: string;
  agentToken: string;
  pipeline: Pipeline;
  refreshOAuthCredential?: (input: OAuthRefreshCommand) => Promise<OAuthRefreshMetadataUpdate>;
  mintGitHubInstallationToken?: (input: {
    installationId: string;
  }) => Promise<{ accessToken: string; expiresAt: string }>;
}

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
  } catch {
    return null;
  }
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

interface MintedInstallationToken {
  accessToken: string;
  mintedAt: number;
}

const mintedTokenCache = new Map<string, MintedInstallationToken>();

/** Test seam: the mint cache is enclave-process-lifetime by design (module-level). */
export function resetMintedTokenCache(): void {
  mintedTokenCache.clear();
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
  options: { bypassCache?: boolean } = {},
): Promise<GitHubMintOutcome> {
  if (!mint) throw new Error('github_installation_token_minting_unavailable');
  if (!installationId) throw new Error('github_installation_id_missing');
  const cacheKey = `github-installation:${installationId}`;
  if (!options.bypassCache) {
    const cached = mintedTokenCache.get(cacheKey);
    if (cached && Date.now() - cached.mintedAt < MINT_TOKEN_TTL_MS) {
      return { outcome: 'token', accessToken: cached.accessToken };
    }
  }
  try {
    const minted = await mint({ installationId });
    if (!minted.accessToken) throw new Error('github_mint_failed');
    mintedTokenCache.set(cacheKey, { accessToken: minted.accessToken, mintedAt: Date.now() });
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
  connection: Pick<DecryptedSourceConnection, 'accessToken' | 'kind' | 'installationId'>,
  mintGitHubInstallationToken?: PullRunnerDeps['mintGitHubInstallationToken'],
): Promise<string | null> {
  if (kind !== 'github' && kind !== 'code') return connection.accessToken;
  const minted = await mintGitHubInstallationTokenForPull(
    connection.installationId,
    mintGitHubInstallationToken,
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
export function buildConnector(kind: string, token: string): Connector | null {
  const deps: PullConnectorDeps = {
    logger: consoleLogger,
    token,
    httpsProxyAgent: externalHttpsProxyAgent(),
    gmailLabelAllowlist: parseAllowlist(process.env['EMAIL_GMAIL_LABEL_ALLOWLIST']),
    m365FolderAllowlist: parseAllowlist(process.env['EMAIL_M365_FOLDER_ALLOWLIST']),
  };
  return createPullConnector(kind, deps);
}

/** Handles a single content-free `pull-due` signal end to end, in-enclave. */
export async function runPull(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connectorBuilder: (kind: string, token: string) => Connector | null = buildConnector,
): Promise<ProcessedFact[]> {
  const connection = await getDecryptedConnectionForKind(
    deps.controlPlaneUrl,
    deps.deploymentId,
    deps.agentToken,
    message.kind,
    deps.orgId,
    deps.crypto,
    deps.controlPlaneFetch,
  );
  if (!connection) {
    console.warn('pull-due: no source connection for kind', message.kind);
    return [];
  }

  const isCode = message.kind === 'code';
  // The code cursor loads BEFORE the mint so a mint-403 early return can bump its tick.
  const storedCursor = isCode ? await loadCodeCursor(deps, message) : null;

  const token = await resolveSourceToken(
    message.kind,
    connection,
    deps.mintGitHubInstallationToken,
  );
  if (!token) {
    if (isCode) {
      await saveCodeCursor(deps, message, advanceCodeCursorTick(storedCursor));
    } else {
      console.warn('pull-due: no usable source token for kind', message.kind);
    }
    return [];
  }
  const connector = connectorBuilder(message.kind, token);
  if (!connector) {
    console.warn('pull-due: no connector implementation for kind', message.kind);
    return [];
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
  );

  if (isCode) {
    await saveCodeCursor(
      deps,
      message,
      result.earlyReturn ? advanceCodeCursorTick(result.cursor.value) : result.cursor.value,
    );
  } else {
    await saveCursor(deps.ssm, message.tenant_id, message.sourceId, result.cursor.value);
  }

  return deps.pipeline.handlePulled(result.facts, result.containers, message.kind);
}

export async function pullWithRefresh(
  message: PullDueMessage,
  deps: PullRunnerDeps,
  connection: DecryptedSourceConnection,
  connector: Connector,
  window: PullWindow,
  connectorBuilder: (kind: string, token: string) => Connector | null = buildConnector,
) {
  try {
    return await connector.pull(window.cursor, window.options);
  } catch (error) {
    if (!isUnauthorized(error)) throw error;
    if (connection.kind === 'github' || connection.kind === 'code') {
      return retryPullWithFreshGitHubToken(deps, connection, window, connectorBuilder, error);
    }
    if (!deps.refreshOAuthCredential) throw error;
    if (!connection.encryptedRefreshToken || !connection.refreshCiphertextSha256) throw error;
    const command = oauthRefreshCommandSchema.parse({
      encryptedRefreshToken: connection.encryptedRefreshToken,
      orgId: deps.orgId,
      deploymentId: deps.deploymentId,
      sourceKind: message.kind,
      connectionId: connection.connectionId,
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
    const refreshed = await getDecryptedConnectionForKind(
      deps.controlPlaneUrl,
      deps.deploymentId,
      deps.agentToken,
      message.kind,
      deps.orgId,
      deps.crypto,
      deps.controlPlaneFetch,
    );
    if (!refreshed) throw error;
    const refreshedToken = await resolveSourceToken(message.kind, refreshed);
    if (!refreshedToken) throw error;
    const refreshedConnector = connectorBuilder(message.kind, refreshedToken);
    if (!refreshedConnector) throw error;
    return refreshedConnector.pull(window.cursor, window.options);
  }
}

// A github/code pull has no refresh token: re-mint the ~1h install token and retry once.
// The retry mint bypasses the TTL cache — recovery is always a fresh mint.
async function retryPullWithFreshGitHubToken(
  deps: PullRunnerDeps,
  connection: DecryptedSourceConnection,
  window: PullWindow,
  connectorBuilder: (kind: string, token: string) => Connector | null,
  originalError: unknown,
) {
  if (!deps.mintGitHubInstallationToken || !connection.installationId) throw originalError;
  const minted = await mintGitHubInstallationTokenForPull(
    connection.installationId,
    deps.mintGitHubInstallationToken,
    { bypassCache: true },
  );
  if (minted.outcome === 'rate_limited') {
    if (connection.kind === 'code') {
      return {
        facts: [],
        containers: [],
        cursor: window.cursor,
        hasMore: false,
        earlyReturn: true,
      };
    }
    throw new Error('github_mint_rate_limited');
  }
  const connector = connectorBuilder(connection.kind, minted.accessToken);
  if (!connector) throw originalError;
  return connector.pull(window.cursor, window.options);
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
