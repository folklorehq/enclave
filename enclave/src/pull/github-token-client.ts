/** Requests a scoped GitHub installation token from the control plane (S1, ADL #42) — the App private key never enters the enclave, and the installation is fixed to this deployment's own by the control plane. */

interface InstallationTokenResponse {
  token: string;
  expiresAt: string;
}

export async function fetchGitHubInstallationToken(
  controlPlaneUrl: string,
  deploymentId: string,
  agentToken: string,
): Promise<string> {
  const res = await fetch(
    `${controlPlaneUrl}/v1/deployments/${deploymentId}/github/installation-token`,
    { method: 'POST', headers: { authorization: `Bearer ${agentToken}` } },
  );
  if (!res.ok) {
    throw new Error(`mint github installation token failed: ${res.status}`);
  }
  const body = (await res.json()) as InstallationTokenResponse;
  return body.token;
}
