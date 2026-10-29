import type { S3Client } from '@aws-sdk/client-s3';
import type {
  CodebaseGraphEraseCommand,
  CodebaseGraphEraseResponse,
} from '@folklore/contracts/enclave';
import type { TenantContext } from '../tenant/tenant-context.js';
import { CODE_GRAPH_ERASE_UNAVAILABLE } from './code-graph-failure.js';
import { CodeGraphNameStore } from './CodeGraphNameStore.js';
import { resolveCodeGraphConsent, UNRECORDED_TOMBSTONE_MARKER } from './CodeGraphConsent.js';
import { CodebaseSelectionStore } from './CodebaseSelectionStore.js';
import { GitHubCodebaseConnectionResolver } from './GitHubCodebaseConnectionResolver.js';

export interface CodebaseGraphEraserDeps {
  s3: S3Client | undefined;
  resolveTenant(orgId: string): TenantContext;
  controlPlaneUrl: string;
  runtimeDeploymentId: string;
  agentToken: () => string;
  fetchImpl: typeof globalThis.fetch;
}

/** Runs a control-plane erase command against the org's sealed code-graph names. */
export class CodebaseGraphEraser {
  constructor(private readonly deps: CodebaseGraphEraserDeps) {}

  async erase(command: CodebaseGraphEraseCommand): Promise<CodebaseGraphEraseResponse> {
    const { s3 } = this.deps;
    if (!s3) throw new Error(CODE_GRAPH_ERASE_UNAVAILABLE);
    const tenant = this.deps.resolveTenant(command.orgId);
    const scope = tenant.processedOutputsScope();
    const resolver = new GitHubCodebaseConnectionResolver({
      controlPlaneUrl: this.deps.controlPlaneUrl,
      runtimeDeploymentId: this.deps.runtimeDeploymentId,
      tenantDeploymentId: scope.deploymentId,
      agentToken: this.deps.agentToken(),
      orgId: command.orgId,
      crypto: tenant.crypto,
      fetchImpl: this.deps.fetchImpl,
      selectionStore: new CodebaseSelectionStore({
        s3,
        bucket: scope.bucket,
        crypto: scope.crypto,
      }),
    });
    const names = new CodeGraphNameStore({ s3, bucket: scope.bucket, crypto: scope.crypto });
    return names.eraseOrg(
      command.orgId,
      command.retiredGeneration,
      () =>
        resolveCodeGraphConsent(
          () => resolver.resolveGraphConsent(),
          async () => UNRECORDED_TOMBSTONE_MARKER,
        ),
      { eraseId: command.eraseId, pass: command.pass },
    );
  }
}
