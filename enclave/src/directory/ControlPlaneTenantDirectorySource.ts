import { directorySyncSchema, type DirectorySync } from '@folklore/contracts';
import type { DirectorySourcePort } from '@folklore/wiki';
import { assertControlPlaneOrigin } from '../pull/control-plane-url.js';

const REQUEST_TIMEOUT_MS = 10_000;
const HTTP_NOT_FOUND = 404;

export const DIRECTORY_RESPONSE_INVALID = 'directory_response_invalid';
export const DIRECTORY_ORG_MISMATCH = 'directory_org_mismatch';
const DIRECTORY_FETCH_FAILED = 'directory_fetch_failed';

export interface ControlPlaneTenantDirectorySourceDeps {
  readonly controlPlaneUrl: string;
  readonly runtimeDeploymentId: string;
  readonly tenantDeploymentId: string;
  readonly orgId: string;
  readonly agentToken: () => string;
  readonly fetchImpl: typeof globalThis.fetch;
}

/** One assigned tenant's directory projection, read from the control plane by this runtime. */
export class ControlPlaneTenantDirectorySource implements DirectorySourcePort {
  constructor(private readonly deps: ControlPlaneTenantDirectorySourceDeps) {
    assertControlPlaneOrigin(deps.controlPlaneUrl);
  }

  async fetch(): Promise<DirectorySync | null> {
    const token = this.deps.agentToken();
    if (!token) throw new Error('directory_agent_token_missing');
    const response = await this.deps.fetchImpl(this.directoryUrl(), {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
      redirect: 'error',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (response.status === HTTP_NOT_FOUND) return null;
    // The status and body stay out of the message: an error body can quote roster entries.
    if (!response.ok) throw new Error(DIRECTORY_FETCH_FAILED);
    return this.parse(await this.readBody(response));
  }

  // Both errors can quote the body, so they become fixed codes; only unparseable JSON is a refusal.
  private async readBody(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch (error) {
      throw new Error(
        error instanceof SyntaxError ? DIRECTORY_RESPONSE_INVALID : DIRECTORY_FETCH_FAILED,
      );
    }
  }

  private directoryUrl(): string {
    const query = new URLSearchParams({
      orgId: this.deps.orgId,
      tenantDeploymentId: this.deps.tenantDeploymentId,
    });
    const deployment = encodeURIComponent(this.deps.runtimeDeploymentId);
    return `${this.deps.controlPlaneUrl}/v1/deployments/${deployment}/directory?${query.toString()}`;
  }

  private parse(body: unknown): DirectorySync {
    const parsed = directorySyncSchema.safeParse(body);
    if (!parsed.success) throw new Error(DIRECTORY_RESPONSE_INVALID);
    if (parsed.data.orgId !== this.deps.orgId) throw new Error(DIRECTORY_ORG_MISMATCH);
    return parsed.data;
  }
}
