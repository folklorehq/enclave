/**
 * Drives one connector `pull()` pass entirely inside the enclave (ADL #42): the
 * worker only ever sends a content-free "pull-due" signal (source id/kind, no
 * token); this module fetches+decrypts the OAuth token here, runs the connector,
 * and hands the normalized output straight to the pipeline in-process — plaintext
 * never leaves the enclave.
 */
import type { KeyObject } from 'node:crypto';
import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import type { Logger } from '@folklore/core';
import {
  type Connector,
  type PullOptions,
  type SyncCursor,
  github,
  intercom,
  jira,
  linear,
  notion,
  slack,
} from '@folklore/connectors';
import type { PullDueMessage } from '@folklore/contracts/enclave';
import type { Pipeline, ProcessedFact } from '../pipeline/index.js';
import {
  getDecryptedConnectionForKind,
  type DecryptedSourceConnection,
} from './source-connections-client.js';

export type { PullDueMessage };

// Content-free completion signal the worker uses to advance sync health (ADL #38); the
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

// ADL #29: the enclave (not the worker signal) owns the uniform 12-month backfill horizon,
// so no wire message can widen how far back a pull reaches.
const BACKFILL_WINDOW_MONTHS = 12;

// The GitHub App id + private key are Folklore-held credentials read at runtime (ADL #35);
// only the SSM paths appear in this public-mirrored source, never the key material.
const GITHUB_APP_ID_SSM_PATH = '/folklore/github-app/app-id';
const GITHUB_APP_PRIVATE_KEY_SSM_PATH = '/folklore/github-app/private-key';

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
  privateKey: KeyObject;
  controlPlaneUrl: string;
  deploymentId: string;
  agentToken: string;
  pipeline: Pipeline;
}

const consoleLogger: Logger = {
  trace: (msg, ctx) => console.debug(msg, ctx ?? ''),
  debug: (msg, ctx) => console.debug(msg, ctx ?? ''),
  info: (msg, ctx) => console.info(msg, ctx ?? ''),
  warn: (msg, ctx) => console.warn(msg, ctx ?? ''),
  error: (msg, ctx) => console.error(msg, ctx ?? ''),
  fatal: (msg, ctx) => console.error(msg, ctx ?? ''),
  child: () => consoleLogger,
};

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

async function getRequiredParameter(
  ssm: SSMClient,
  name: string,
  withDecryption: boolean,
): Promise<string> {
  const resp = await ssm.send(
    new GetParameterCommand({ Name: name, WithDecryption: withDecryption }),
  );
  const value = resp.Parameter?.Value;
  if (!value) throw new Error(`missing SSM parameter ${name}`);
  return value;
}

async function loadGitHubAppCredentials(ssm: SSMClient): Promise<github.GitHubAppCredentials> {
  const [appId, privateKey] = await Promise.all([
    getRequiredParameter(ssm, GITHUB_APP_ID_SSM_PATH, false),
    getRequiredParameter(ssm, GITHUB_APP_PRIVATE_KEY_SSM_PATH, true),
  ]);
  return { appId, privateKey };
}

// GitHub is a GitHub App: the stored connection is the installation id, so mint a
// short-lived installation token here rather than treating it as a bearer token.
export async function resolveSourceToken(
  kind: string,
  connection: DecryptedSourceConnection,
  ssm: SSMClient,
): Promise<string> {
  if (kind === 'github') {
    const credentials = await loadGitHubAppCredentials(ssm);
    return github.mintInstallationToken(credentials, connection.accessToken);
  }
  return connection.accessToken;
}

export function buildConnector(kind: string, token: string): Connector | null {
  switch (kind) {
    case 'github':
      return new github.GitHubConnector(
        { logger: consoleLogger },
        new github.OctokitGitHubClient(token),
      );
    case 'slack':
      return new slack.SlackConnector({ logger: consoleLogger }, new slack.HttpSlackClient(token));
    case 'notion':
      return new notion.NotionConnector({ logger: consoleLogger }, new notion.NotionClient(token));
    case 'linear':
      return new linear.LinearConnector(
        { logger: consoleLogger },
        new linear.LinearSdkClient(token),
      );
    case 'jira':
      return new jira.JiraConnector({ logger: consoleLogger }, new jira.JiraHttpClient(token));
    case 'intercom':
      return new intercom.IntercomConnector(
        { logger: consoleLogger },
        new intercom.IntercomSdkClient(token),
      );
    default:
      return null;
  }
}

/** Handles a single content-free `pull-due` signal end to end, in-enclave. */
export async function runPull(
  message: PullDueMessage,
  deps: PullRunnerDeps,
): Promise<ProcessedFact[]> {
  const connection = await getDecryptedConnectionForKind(
    deps.controlPlaneUrl,
    deps.deploymentId,
    deps.agentToken,
    message.kind,
    deps.privateKey,
  );
  if (!connection) {
    console.warn('pull-due: no source connection for kind', message.kind);
    return [];
  }

  const token = await resolveSourceToken(message.kind, connection, deps.ssm);
  const connector = buildConnector(message.kind, token);
  if (!connector) {
    console.warn('pull-due: no connector implementation for kind', message.kind);
    return [];
  }

  const storedCursor = await loadCursor(deps.ssm, message.tenant_id, message.sourceId);
  const window = resolvePullWindow(message.backfill, storedCursor);
  const result = await connector.pull(window.cursor, window.options);

  await saveCursor(deps.ssm, message.tenant_id, message.sourceId, result.cursor.value);

  return deps.pipeline.handlePulled(result.facts, result.containers, message.kind);
}
