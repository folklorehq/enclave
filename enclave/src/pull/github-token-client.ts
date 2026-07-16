/** Requests a scoped GitHub installation token from the control plane (S1, ADL #42) — the App private key never enters the enclave, and the installation is fixed to this deployment's own by the control plane. The token arrives ECIES-sealed to this enclave's public key and is decrypted here. */
import type { KeyObject } from 'node:crypto';
import type { EncryptedInstallationToken } from '@folklore/contracts/enclave';
import { decryptPayload, type EncryptedPayload } from '../ingest/receiver.js';

// Null (not throw) when the control plane omits the connection — mint/seal failure or a revoked
// install surface as 404; the caller then skips the github pull and retries next pull-due (design §3).
export async function fetchGitHubInstallationToken(
  controlPlaneUrl: string,
  deploymentId: string,
  agentToken: string,
  privateKey: KeyObject,
): Promise<string | null> {
  const res = await fetch(
    `${controlPlaneUrl}/v1/deployments/${deploymentId}/github/installation-token`,
    { method: 'POST', headers: { authorization: `Bearer ${agentToken}` } },
  );
  if (!res.ok) {
    console.warn('pull-due: github installation token unavailable', res.status);
    return null;
  }
  const body = (await res.json()) as EncryptedInstallationToken;
  const msg = JSON.parse(body.encryptedToken) as EncryptedPayload;
  return decryptPayload(msg, privateKey).toString('utf8');
}
