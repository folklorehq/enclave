/** Fetches ESDK-sealed source credentials and decrypts them in the owning tenant context. */
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { sha256Hex } from '@folklore/utils';
import { assertControlPlaneOrigin } from './control-plane-url.js';

export interface RawSourceConnection {
  connectionId: string;
  orgId: string | null;
  attestationGeneration: string | null;
  accessCiphertextSha256: string | null;
  refreshCiphertextSha256: string | null;
  kind: string;
  encryptedAccessToken: string;
  encryptedRefreshToken?: string | null;
  sourceUserId?: string | null;
  installationId?: string | null;
}

export interface DecryptedSourceConnection {
  kind: string;
  connectionId: string;
  attestationGeneration: string;
  accessToken: string;
  refreshToken?: string;
  encryptedRefreshToken?: string;
  refreshCiphertextSha256?: string;
  sourceUserId?: string;
  installationId?: string;
}

async function fetchSourceConnections(
  controlPlaneUrl: string,
  deploymentId: string,
  agentToken: string,
  orgId: string,
  fetchImpl: typeof globalThis.fetch,
): Promise<RawSourceConnection[]> {
  assertControlPlaneOrigin(controlPlaneUrl);
  // Fail closed: an org-scoped pull never makes a wide unfiltered connections fetch.
  if (!orgId) throw new Error('source_connections_org_required');
  const res = await fetchImpl(
    `${controlPlaneUrl.replace(/\/$/, '')}/v1/deployments/${encodeURIComponent(deploymentId)}/source-connections?orgId=${encodeURIComponent(orgId)}`,
    {
      headers: { authorization: `Bearer ${agentToken}` },
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    },
  );
  if (!res.ok) {
    throw new Error(`fetch source connections failed: ${res.status}`);
  }
  const body = (await res.json()) as { connections: RawSourceConnection[] };
  return body.connections;
}

async function decryptToken(
  encrypted: string,
  crypto: EnclaveCrypto,
  ref: {
    orgId: string;
    sourceKind: string;
    connectionId: string;
    purpose: 'access' | 'refresh';
    generation: string;
  },
): Promise<string> {
  const ciphertext = Buffer.from(encrypted, 'base64');
  const plaintext = await crypto.decryptOAuthCredential(ciphertext, ref);
  try {
    return plaintext.toString('utf8');
  } finally {
    plaintext.fill(0);
    ciphertext.fill(0);
  }
}

/** The one connection matching `kind` for this deployment, decrypted, or null if not connected. */
export async function getDecryptedConnectionForKind(
  controlPlaneUrl: string,
  deploymentId: string,
  agentToken: string,
  kind: string,
  orgId: string,
  crypto: EnclaveCrypto,
  fetchImpl: typeof globalThis.fetch,
): Promise<DecryptedSourceConnection | null> {
  const connections = await fetchSourceConnections(
    controlPlaneUrl,
    deploymentId,
    agentToken,
    orgId,
    fetchImpl,
  );
  const match = connections.find((c) => c.kind === kind && c.orgId === orgId);
  if (!match) return null;

  if (
    match.attestationGeneration === null ||
    match.accessCiphertextSha256 === null ||
    match.accessCiphertextSha256 !== sha256Hex(match.encryptedAccessToken) ||
    (match.encryptedRefreshToken !== null &&
      match.encryptedRefreshToken !== undefined &&
      (match.refreshCiphertextSha256 === null ||
        match.refreshCiphertextSha256 === undefined ||
        match.refreshCiphertextSha256 !== sha256Hex(match.encryptedRefreshToken)))
  ) {
    return null;
  }
  return {
    kind: match.kind,
    connectionId: match.connectionId,
    attestationGeneration: match.attestationGeneration,
    accessToken: await decryptToken(match.encryptedAccessToken, crypto, {
      orgId,
      sourceKind: match.kind,
      connectionId: match.connectionId,
      purpose: 'access',
      generation: match.attestationGeneration,
    }),
    refreshToken: match.encryptedRefreshToken
      ? await decryptToken(match.encryptedRefreshToken, crypto, {
          orgId,
          sourceKind: match.kind,
          connectionId: match.connectionId,
          purpose: 'refresh',
          generation: match.attestationGeneration,
        })
      : undefined,
    ...(match.encryptedRefreshToken
      ? {
          encryptedRefreshToken: match.encryptedRefreshToken,
          refreshCiphertextSha256: match.refreshCiphertextSha256 ?? undefined,
        }
      : {}),
    sourceUserId: match.sourceUserId ?? undefined,
    installationId: match.installationId ?? undefined,
  };
}
