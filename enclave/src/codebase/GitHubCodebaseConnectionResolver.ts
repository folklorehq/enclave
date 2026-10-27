import type { EnclaveCrypto } from '../crypto/esdk.js';
import type {
  DecryptedSourceConnection,
  RawSourceConnection,
  SourceConnectionResolution,
} from '../pull/source-connections-client.js';
import {
  decryptSourceConnection,
  fetchSourceConnections,
} from '../pull/source-connections-client.js';
import {
  DEFAULT_CODEBASE_SELECTION,
  isCodebaseSelectionMissing,
  type CodebaseSelection,
} from './CodebaseSelectionStore.js';

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

export type CodebaseConsentResolution =
  | {
      outcome: 'ready';
      selection: CodebaseSelection;
      capabilityGeneration: string;
      deploymentId: string;
    }
  | Extract<CodebaseConnectionResolution, { outcome: 'not_ready' | 'not_processed' }>;

type ParentResolution =
  | {
      outcome: 'connected';
      connection: DecryptedSourceConnection;
      capabilityGeneration?: string;
    }
  | ParentRefusal;

type ParentRefusal =
  | {
      outcome: 'not_ready';
      reason:
        | 'codebase_capability_missing'
        | 'codebase_capability_disabled'
        | 'codebase_parent_missing'
        | 'github_parent_missing';
    }
  | Extract<SourceConnectionResolution, { outcome: 'not_processed' }>;

type LocatedParent =
  | { outcome: 'located'; parent: RawSourceConnection; capabilityGeneration?: string }
  | ParentRefusal;

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
    if (parent.outcome !== 'connected') return this.refusal(parent);
    const readiness = await this.readReadiness(parent.capabilityGeneration);
    if (readiness.outcome !== 'ready') return readiness;
    return { ...readiness, connection: parent.connection };
  }

  async resolveGraphConsent(): Promise<CodebaseConsentResolution> {
    const located = await this.locateParent(true);
    if (located.outcome !== 'located') return this.refusal(located);
    const readiness = await this.readReadiness(located.capabilityGeneration);
    if (readiness.outcome !== 'ready') return readiness;
    return { ...readiness, deploymentId: this.deps.tenantDeploymentId };
  }

  private refusal(
    parent: ParentRefusal,
  ): Extract<CodebaseConnectionResolution, { outcome: 'not_ready' | 'not_processed' }> {
    if (parent.outcome !== 'not_ready') return parent;
    if (
      parent.reason === 'codebase_capability_missing' ||
      parent.reason === 'codebase_capability_disabled'
    ) {
      return { outcome: 'not_ready', reason: parent.reason };
    }
    return { outcome: 'not_ready', reason: 'codebase_parent_missing' };
  }

  private async readReadiness(
    capabilityGeneration: string | undefined,
  ): Promise<
    | { outcome: 'ready'; selection: CodebaseSelection; capabilityGeneration: string }
    | Extract<CodebaseConnectionResolution, { outcome: 'not_ready' }>
  > {
    try {
      const selection = await this.readSelection();
      if (selection.mode === 'selected' && selection.repositories.length === 0) {
        return { outcome: 'not_ready', reason: 'codebase_selection_unavailable' };
      }
      if (!capabilityGeneration) {
        return { outcome: 'not_ready', reason: 'codebase_capability_missing' };
      }
      return { outcome: 'ready', selection, capabilityGeneration };
    } catch {
      return { outcome: 'not_ready', reason: 'codebase_selection_unavailable' };
    }
  }

  private async readSelection(): Promise<CodebaseSelection> {
    try {
      return await this.deps.selectionStore.read({
        orgId: this.deps.orgId,
        deploymentId: this.deps.tenantDeploymentId,
      });
    } catch (error) {
      if (isCodebaseSelectionMissing(error)) return DEFAULT_CODEBASE_SELECTION;
      throw error;
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

  private async resolveParent(requireCapability: boolean): Promise<ParentResolution> {
    const located = await this.locateParent(requireCapability);
    if (located.outcome !== 'located') return located;
    const decrypted = await decryptSourceConnection(
      located.parent,
      this.deps.tenantDeploymentId,
      this.deps.orgId,
      this.deps.crypto,
    );
    if (decrypted.outcome !== 'connected') {
      return decrypted.outcome === 'missing'
        ? { outcome: 'not_ready', reason: 'github_parent_missing' }
        : decrypted;
    }
    return {
      ...decrypted,
      ...(located.capabilityGeneration
        ? { capabilityGeneration: located.capabilityGeneration }
        : {}),
    };
  }

  private async locateParent(requireCapability: boolean): Promise<LocatedParent> {
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
      if (fetched.outcome === 'connected') {
        return { outcome: 'not_processed', reason: 'connection_response_invalid' };
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
    const parent = parents[0];
    if (parents.length !== 1 || !parent) {
      return { outcome: 'not_processed', reason: 'connection_response_invalid' };
    }
    const capability = fetched.projection.capabilities[0];
    if (requireCapability) {
      if (!capability) return { outcome: 'not_ready', reason: 'codebase_capability_missing' };
      if (!capability.isEnabled) {
        return { outcome: 'not_ready', reason: 'codebase_capability_disabled' };
      }
    }
    return {
      outcome: 'located',
      parent,
      ...(requireCapability && capability
        ? { capabilityGeneration: capability.activationGeneration }
        : {}),
    };
  }
}
