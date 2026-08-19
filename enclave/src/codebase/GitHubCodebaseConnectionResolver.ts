import type { EnclaveCrypto } from '../crypto/esdk.js';
import type {
  DecryptedSourceConnection,
  SourceConnectionResolution,
} from '../pull/source-connections-client.js';
import {
  decryptSourceConnection,
  fetchSourceConnections,
} from '../pull/source-connections-client.js';
import type { CodebaseSelection } from './CodebaseSelectionStore.js';

export type CodebaseConnectionResolution =
  | {
      outcome: 'ready';
      connection: DecryptedSourceConnection;
      selection: CodebaseSelection;
      capabilityGeneration: string;
    }
  | {
      outcome: 'not_ready';
      reason:
        | 'codebase_capability_missing'
        | 'codebase_capability_disabled'
        | 'codebase_parent_missing'
        | 'codebase_selection_missing'
        | 'codebase_selection_unavailable';
    }
  | Extract<SourceConnectionResolution, { outcome: 'not_processed' }>;

export interface GitHubCodebaseConnectionResolverDeps {
  controlPlaneUrl: string;
  runtimeDeploymentId: string;
  tenantDeploymentId: string;
  agentToken: string;
  orgId: string;
  crypto: EnclaveCrypto;
  fetchImpl: typeof globalThis.fetch;
  selectionStore: Pick<CodebaseSelectionStore, 'read'>;
}

interface CodebaseSelectionStore {
  read(input: { orgId: string; deploymentId: string }): Promise<CodebaseSelection>;
}

/** Resolves Codebase only through the matching GitHub parent observed by the enclave. */
export class GitHubCodebaseConnectionResolver {
  constructor(private readonly deps: GitHubCodebaseConnectionResolverDeps) {}

  async resolveScheduled(): Promise<CodebaseConnectionResolution> {
    const parent = await this.resolveParent(true);
    if (parent.outcome !== 'connected') {
      if (parent.outcome === 'not_ready') {
        if (parent.reason === 'github_parent_missing') {
          return { outcome: 'not_ready', reason: 'codebase_parent_missing' };
        }
        if (parent.reason === 'codebase_capability_missing') {
          return { outcome: 'not_ready', reason: 'codebase_capability_missing' };
        }
        if (parent.reason === 'codebase_capability_disabled') {
          return { outcome: 'not_ready', reason: 'codebase_capability_disabled' };
        }
        return { outcome: 'not_ready', reason: 'codebase_parent_missing' };
      }
      return parent;
    }
    try {
      const selection = await this.deps.selectionStore.read({
        orgId: this.deps.orgId,
        deploymentId: this.deps.tenantDeploymentId,
      });
      if (selection.mode === 'selected' && selection.repositories.length === 0) {
        return { outcome: 'not_ready', reason: 'codebase_selection_unavailable' };
      }
      if (!parent.capabilityGeneration) {
        return { outcome: 'not_ready', reason: 'codebase_capability_missing' };
      }
      return {
        outcome: 'ready',
        connection: parent.connection,
        selection,
        capabilityGeneration: parent.capabilityGeneration,
      };
    } catch (error) {
      return {
        outcome: 'not_ready',
        reason:
          error instanceof Error && error.message === 'codebase_selection_missing'
            ? 'codebase_selection_missing'
            : 'codebase_selection_unavailable',
      };
    }
  }

  /** Interactive repository management requires a GitHub parent, never an enabled Codebase child. */
  async resolveInteractive(): Promise<
    | { outcome: 'ready'; connection: DecryptedSourceConnection }
    | { outcome: 'not_ready'; reason: 'codebase_parent_missing' }
    | Extract<SourceConnectionResolution, { outcome: 'not_processed' }>
  > {
    const parent = await this.resolveParent(false);
    if (parent.outcome === 'connected') return { outcome: 'ready', connection: parent.connection };
    if (parent.outcome === 'not_ready')
      return { outcome: 'not_ready', reason: 'codebase_parent_missing' };
    return parent;
  }

  private async resolveParent(requireCapability: boolean): Promise<
    | {
        outcome: 'connected';
        connection: DecryptedSourceConnection;
        capabilityGeneration?: string;
      }
    | {
        outcome: 'not_ready';
        reason:
          | 'codebase_capability_missing'
          | 'codebase_capability_disabled'
          | 'codebase_parent_missing'
          | 'github_parent_missing';
      }
    | Extract<SourceConnectionResolution, { outcome: 'not_processed' }>
  > {
    const fetched = await fetchSourceConnections(
      this.deps.controlPlaneUrl,
      this.deps.runtimeDeploymentId,
      this.deps.tenantDeploymentId,
      this.deps.agentToken,
      this.deps.orgId,
      this.deps.fetchImpl,
      'capabilities',
    );
    if (fetched.outcome !== 'fetched') {
      if (fetched.outcome === 'missing') {
        return { outcome: 'not_ready', reason: 'github_parent_missing' };
      }
      return fetched;
    }
    if (
      fetched.projection.connections.some(
        (connection) =>
          connection.deploymentId !== this.deps.tenantDeploymentId ||
          connection.orgId !== this.deps.orgId,
      )
    ) {
      return { outcome: 'not_processed', reason: 'connection_integrity_failed' };
    }
    const parents = fetched.projection.connections.filter(
      (connection) => connection.kind === 'github',
    );
    if (parents.length === 0) {
      return {
        outcome: 'not_ready',
        reason: requireCapability ? 'codebase_parent_missing' : 'github_parent_missing',
      };
    }
    if (parents.length !== 1)
      return { outcome: 'not_processed', reason: 'connection_response_invalid' };
    if (requireCapability) {
      const capability = fetched.projection.capabilities[0];
      if (!capability) return { outcome: 'not_ready', reason: 'codebase_capability_missing' };
      if (!capability.isEnabled) {
        return { outcome: 'not_ready', reason: 'codebase_capability_disabled' };
      }
    }
    const parent = parents[0];
    if (!parent) return { outcome: 'not_processed', reason: 'connection_response_invalid' };
    const decrypted = await decryptSourceConnection(
      parent,
      this.deps.tenantDeploymentId,
      this.deps.orgId,
      this.deps.crypto,
    );
    if (decrypted.outcome !== 'connected') {
      return decrypted.outcome === 'missing'
        ? { outcome: 'not_ready', reason: 'github_parent_missing' }
        : decrypted;
    }
    const capabilityGeneration = requireCapability
      ? fetched.projection.capabilities[0]?.activationGeneration
      : undefined;
    return {
      ...decrypted,
      ...(capabilityGeneration ? { capabilityGeneration } : {}),
    };
  }
}
