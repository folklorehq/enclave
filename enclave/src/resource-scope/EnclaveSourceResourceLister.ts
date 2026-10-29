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
import type { SourceResourceLister } from './EnclaveResourceScopeAdapter.js';

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

  async listResources(target: SourceTarget): Promise<NormalizedResource[]> {
    const opened = await this.open(target);
    try {
      return await opened.connector.listResources();
    } catch (error) {
      if (!isUnauthorized(error)) throw error;
      const fresh = await this.refreshed(target, opened.connection, error);
      return fresh.listResources();
    }
  }

  private async open(target: SourceTarget): Promise<OpenedConnector> {
    const resolved = await this.resolve(target);
    if (resolved.outcome !== 'connected') throw new Error(CONNECTION_UNAVAILABLE);
    const token = await resolveSourceToken(
      target.sourceKind,
      resolved.connection,
      this.deps.mintGitHubInstallationToken,
      { orgId: target.orgId },
    );
    if (!token) throw new Error(CONNECTION_UNAVAILABLE);
    const connector = this.build(target.sourceKind, token, resolved.connection);
    if (!connector) throw new Error(CONNECTION_UNAVAILABLE);
    return { connector, connection: resolved.connection };
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
