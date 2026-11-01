import type { Connector, NormalizedResource } from '@folklore/connectors';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  buildConnector,
  connectionMetadata,
  isUnauthorized,
  refreshConnectorAfterUnauthorized,
  resolveSourceToken,
  type PullRunnerDeps,
} from '../pull/pull-runner.js';
import {
  getDecryptedConnectionForKind,
  type DecryptedSourceConnection,
  type SourceConnectionResolution,
} from '../pull/source-connections-client.js';
import type { SourceResourceLister, SourceResourceListing } from './ports.js';

export interface EnclaveSourceResourceListerDeps {
  controlPlaneUrl: string;
  runtimeDeploymentId: string;
  agentToken: () => string;
  fetchImpl: typeof globalThis.fetch;
  resolveTenant(orgId: string): {
    crypto: EnclaveCrypto;
    processedOutputsScope(): { deploymentId: string };
  };
  mintGitHubInstallationToken?: PullRunnerDeps['mintGitHubInstallationToken'];
  refreshOAuthCredential?: PullRunnerDeps['refreshOAuthCredential'];
  buildConnector?: typeof buildConnector;
}

interface SourceTarget {
  orgId: string;
  sourceKind: string;
}

interface OpenedConnector {
  connector: Connector;
  connection: DecryptedSourceConnection;
}

const CONNECTION_UNAVAILABLE = 'source_connection_unavailable';

/** Lists an org source's resources live, the way a pull reaches it, including its 401 recovery. */
export class EnclaveSourceResourceLister implements SourceResourceLister {
  constructor(private readonly deps: EnclaveSourceResourceListerDeps) {}

  async listResources(target: SourceTarget): Promise<SourceResourceListing> {
    const opened = await this.open(target);
    const connectionKey = this.keyOf(opened.connection);
    return { connectionKey, resources: await this.listOpened(target, opened) };
  }

  async connectionKey(target: SourceTarget): Promise<string> {
    return this.keyOf(await this.connected(target));
  }

  private async listOpened(
    target: SourceTarget,
    opened: OpenedConnector,
  ): Promise<NormalizedResource[]> {
    try {
      return await opened.connector.listResources();
    } catch (error) {
      if (!isUnauthorized(error)) throw error;
      const fresh = await this.refreshed(target, opened.connection, error);
      return fresh.listResources();
    }
  }

  // A reconnect issues a new connection or activation, so a listing from the old one never matches.
  private keyOf(connection: DecryptedSourceConnection): string {
    return JSON.stringify([connection.connectionId, connection.activationGeneration]);
  }

  private async connected(target: SourceTarget): Promise<DecryptedSourceConnection> {
    const resolved = await this.resolve(target);
    if (resolved.outcome !== 'connected') throw new Error(CONNECTION_UNAVAILABLE);
    return resolved.connection;
  }

  private async open(target: SourceTarget): Promise<OpenedConnector> {
    const connection = await this.connected(target);
    const token = await resolveSourceToken(
      target.sourceKind,
      connection,
      this.deps.mintGitHubInstallationToken,
      { orgId: target.orgId },
    );
    if (!token) throw new Error(CONNECTION_UNAVAILABLE);
    const connector = this.build(target.sourceKind, token, connection);
    if (!connector) throw new Error(CONNECTION_UNAVAILABLE);
    return { connector, connection };
  }

  private async refreshed(
    target: SourceTarget,
    connection: DecryptedSourceConnection,
    originalError: unknown,
  ): Promise<Connector> {
    const tenant = this.deps.resolveTenant(target.orgId);
    const fresh = await refreshConnectorAfterUnauthorized({
      sourceKind: target.sourceKind,
      connection,
      originalError,
      deps: {
        orgId: target.orgId,
        deploymentId: tenant.processedOutputsScope().deploymentId,
        refreshOAuthCredential: this.deps.refreshOAuthCredential,
        mintGitHubInstallationToken: this.deps.mintGitHubInstallationToken,
      },
      reconnect: () => this.resolve(target),
      build: (token, fresher) => this.build(target.sourceKind, token, fresher),
    });
    if (fresh.outcome === 'rate_limited') throw originalError;
    return fresh.connector;
  }

  private resolve(target: SourceTarget): Promise<SourceConnectionResolution> {
    const tenant = this.deps.resolveTenant(target.orgId);
    return getDecryptedConnectionForKind(
      this.deps.controlPlaneUrl,
      this.deps.runtimeDeploymentId,
      tenant.processedOutputsScope().deploymentId,
      this.deps.agentToken(),
      target.sourceKind,
      target.orgId,
      tenant.crypto,
      this.deps.fetchImpl,
    );
  }

  private build(
    sourceKind: string,
    token: string,
    connection: DecryptedSourceConnection,
  ): Connector | null {
    return (this.deps.buildConnector ?? buildConnector)(
      sourceKind,
      token,
      connectionMetadata(connection),
    );
  }
}
