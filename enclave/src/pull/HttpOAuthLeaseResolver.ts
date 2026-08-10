import { assertControlPlaneOrigin } from './control-plane-url.js';

export interface OAuthLeaseResolver {
  resolve(input: { orgId: string; deploymentId: string }): Promise<string | null>;
}

/** Reads the current lease generation over the deployment-authenticated control-plane channel. */
export class HttpOAuthLeaseResolver implements OAuthLeaseResolver {
  constructor(
    private readonly controlPlaneUrl: string,
    private readonly deploymentId: string,
    private readonly agentToken: () => string,
    private readonly fetchImpl: typeof globalThis.fetch,
  ) {
    assertControlPlaneOrigin(controlPlaneUrl);
  }

  async resolve(input: { orgId: string; deploymentId: string }): Promise<string | null> {
    if (input.deploymentId !== this.deploymentId) return null;
    const token = this.agentToken();
    if (!token) return null;
    try {
      const response = await this.fetchImpl(
        `${this.controlPlaneUrl.replace(/\/$/, '')}/v1/deployments/${encodeURIComponent(input.deploymentId)}/oauth-lease`,
        {
          headers: { authorization: `Bearer ${token}` },
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!response.ok) return null;
      const parsed: unknown = await response.json();
      if (!parsed || typeof parsed !== 'object') return null;
      const generation = (parsed as Record<string, unknown>)['attestationGeneration'];
      return typeof generation === 'string' && generation.length > 0 ? generation : null;
    } catch {
      return null;
    }
  }
}
