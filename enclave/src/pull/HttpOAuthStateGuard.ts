import type { OAuthStateGuard } from './EnclaveOAuthAuthorizationService.js';
import { assertControlPlaneOrigin } from './control-plane-url.js';

export class HttpOAuthStateGuard implements OAuthStateGuard {
  constructor(
    private readonly controlPlaneUrl: string,
    private readonly deploymentId: string,
    private readonly agentToken: () => string,
    private readonly fetchImpl: typeof globalThis.fetch,
  ) {
    assertControlPlaneOrigin(controlPlaneUrl);
  }

  async consume(input: Parameters<OAuthStateGuard['consume']>[0]): Promise<boolean> {
    return this.post('/oauth-state/consume', input);
  }

  async consumeMember(input: Parameters<OAuthStateGuard['consumeMember']>[0]): Promise<boolean> {
    return this.post('/member-identity-state/consume', input);
  }

  private async post(
    path: string,
    input: {
      orgId: string;
      deploymentId: string;
      sourceKind: string;
      stateBindingId: string;
    },
  ): Promise<boolean> {
    if (input.deploymentId !== this.deploymentId) return false;
    const token = this.agentToken();
    if (!token) return false;
    try {
      const response = await this.fetchImpl(
        `${this.controlPlaneUrl.replace(/\/$/, '')}/v1/deployments/${encodeURIComponent(this.deploymentId)}${path}`,
        {
          method: 'POST',
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            orgId: input.orgId,
            sourceKind: input.sourceKind,
            stateBindingId: input.stateBindingId,
          }),
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!response.ok) return false;
      const parsed: unknown = await response.json();
      return (
        typeof parsed === 'object' &&
        parsed !== null &&
        (parsed as Record<string, unknown>)['consumed'] === true
      );
    } catch {
      return false;
    }
  }
}
