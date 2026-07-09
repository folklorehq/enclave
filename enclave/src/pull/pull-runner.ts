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
import { type Connector, github, intercom, linear, notion, slack } from '@folklore/connectors';
import type { Pipeline, ProcessedFact } from '../pipeline/index.js';
import { getDecryptedConnectionForKind } from './source-connections-client.js';

export interface PullDueMessage {
  type: 'pull-due';
  tenant_id: string;
  sourceId: string;
  kind: string;
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

  const connector = buildConnector(message.kind, connection.accessToken);
  if (!connector) {
    console.warn('pull-due: no connector implementation for kind', message.kind);
    return [];
  }

  const cursorValue = await loadCursor(deps.ssm, message.tenant_id, message.sourceId);
  const result = await connector.pull({ value: cursorValue });

  await saveCursor(deps.ssm, message.tenant_id, message.sourceId, result.cursor.value);

  return deps.pipeline.handlePulled(result.facts, result.containers, message.kind);
}
