import type { OAuthCredentialPersistenceTransport } from './HttpOAuthCredentialPersistence.js';
import { assertControlPlaneOrigin } from './control-plane-url.js';

export class HttpOAuthPersistenceTransport implements OAuthCredentialPersistenceTransport {
  constructor(
    private readonly controlPlaneUrl: string,
    private readonly deploymentId: string,
    private readonly agentToken: () => string,
    private readonly fetchImpl: typeof globalThis.fetch,
  ) {
    assertControlPlaneOrigin(controlPlaneUrl);
  }

  async post(path: string, body: unknown): Promise<{ status: number }> {
    const token = this.agentToken();
    if (!token) throw new Error('oauth_persistence_auth_unavailable');
    const response = await this.fetchImpl(
      `${this.controlPlaneUrl.replace(/\/$/, '')}/v1/deployments/${encodeURIComponent(this.deploymentId)}${path}`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      },
    );
    return { status: response.status };
  }
}
