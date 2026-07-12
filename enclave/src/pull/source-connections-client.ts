/** Fetches encrypted source-connection tokens from the control plane and decrypts them in-enclave (ADL #42) — the control plane only ever holds ciphertext. */
import type { KeyObject } from 'node:crypto';
import { decryptPayload, type EncryptedPayload } from '../ingest/receiver.js';

export interface RawSourceConnection {
  kind: string;
  encryptedAccessToken: string;
  encryptedRefreshToken?: string | null;
  sourceUserId?: string | null;
}

export interface DecryptedSourceConnection {
  kind: string;
  accessToken: string;
  refreshToken?: string;
  sourceUserId?: string;
}

async function fetchSourceConnections(
  controlPlaneUrl: string,
  deploymentId: string,
  agentToken: string,
): Promise<RawSourceConnection[]> {
  const res = await fetch(`${controlPlaneUrl}/v1/deployments/${deploymentId}/source-connections`, {
    headers: { authorization: `Bearer ${agentToken}` },
  });
  if (!res.ok) {
    throw new Error(`fetch source connections failed: ${res.status}`);
  }
  const body = (await res.json()) as { connections: RawSourceConnection[] };
  return body.connections;
}

function decryptToken(encrypted: string, privateKey: KeyObject): string {
  const msg = JSON.parse(encrypted) as EncryptedPayload;
  return decryptPayload(msg, privateKey).toString('utf8');
}

/** The one connection matching `kind` for this deployment, decrypted, or null if not connected. */
export async function getDecryptedConnectionForKind(
  controlPlaneUrl: string,
  deploymentId: string,
  agentToken: string,
  kind: string,
  privateKey: KeyObject,
): Promise<DecryptedSourceConnection | null> {
  const connections = await fetchSourceConnections(controlPlaneUrl, deploymentId, agentToken);
  const match = connections.find((c) => c.kind === kind);
  if (!match) return null;

  return {
    kind: match.kind,
    accessToken: decryptToken(match.encryptedAccessToken, privateKey),
    refreshToken: match.encryptedRefreshToken
      ? decryptToken(match.encryptedRefreshToken, privateKey)
      : undefined,
    sourceUserId: match.sourceUserId ?? undefined,
  };
}
