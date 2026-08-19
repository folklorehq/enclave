/** Fetches ESDK-sealed source credentials and decrypts them in the owning tenant context. */
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { sha256Hex } from '@folklore/utils';
import {
  type EnclaveSourceConnectionProjection,
  enclaveSourceConnectionProjectionSchema,
  enclaveSourceConnectionsResponseSchema,
  type EncryptedSourceConnection,
  type GitHubCodebaseCapabilityProjection,
} from '@folklore/contracts/enclave';
import { assertControlPlaneOrigin } from './control-plane-url.js';

const emptyWebhookMetadata = {
  externalTenantId: null,
  webhookRouteId: null,
  webhookRevision: 0,
  webhookRegistrationIds: null,
  webhookExpiresAt: null,
  webhookStatus: null,
  webhookLastOperation: null,
  webhookLastAttemptedAt: null,
  webhookLastSucceededAt: null,
  webhookLastDeliveryAt: null,
  webhookProtocolCapture: null,
  webhookProtocolCaptureExpiresAt: null,
  webhookFailureCode: null,
  webhookCleanupRouteId: null,
  webhookCleanupExternalTenantId: null,
  webhookCleanupRegistrationIds: null,
  webhookCleanupExpiresAt: null,
} as const;

export type RawSourceConnection = EnclaveSourceConnectionProjection;

export interface SourceConnectionProjection {
  connections: RawSourceConnection[];
  capabilities: GitHubCodebaseCapabilityProjection[];
}

type SourceConnectionsProtocol = 'legacy' | 'capabilities';

export interface DecryptedSourceConnection {
  kind: string;
  connectionId: string;
  deploymentId: string;
  orgId: string;
  activationGeneration: string;
  attestationGeneration: string;
  accessToken: string;
  refreshToken?: string;
  encryptedRefreshToken?: string;
  refreshCiphertextSha256?: string;
  sourceUserId?: string;
  installationId?: string;
  externalTenantId?: string;
  webhookRouteId: string | null;
  webhookRevision: number;
  webhookRegistrationIds: string[] | null;
  webhookExpiresAt: string | null;
  webhookStatus: 'registered' | 'degraded' | null;
  webhookLastOperation: 'register' | 'refresh' | 'adopt' | 'cleanup' | null;
  webhookLastAttemptedAt: string | null;
  webhookLastSucceededAt: string | null;
  webhookLastDeliveryAt: string | null;
  webhookProtocolCapture: EncryptedSourceConnection['webhookProtocolCapture'];
  webhookProtocolCaptureExpiresAt: string | null;
  webhookFailureCode: 'provider_rejected' | 'provider_error' | 'persist_failed' | null;
  webhookCleanupRouteId: string | null;
  webhookCleanupExternalTenantId: string | null;
  webhookCleanupRegistrationIds: string[] | null;
  webhookCleanupExpiresAt: string | null;
}

export type SourceConnectionResolution =
  | { outcome: 'connected'; connection: DecryptedSourceConnection }
  | { outcome: 'missing' }
  | {
      outcome: 'not_processed';
      reason:
        | 'connection_fetch_failed'
        | 'connection_response_invalid'
        | 'connection_integrity_failed'
        | 'connection_decrypt_failed';
    };

export async function fetchSourceConnections(
  controlPlaneUrl: string,
  runtimeDeploymentId: string,
  tenantDeploymentId: string,
  agentToken: string,
  orgId: string,
  fetchImpl: typeof globalThis.fetch,
  protocol: SourceConnectionsProtocol = 'legacy',
): Promise<
  { outcome: 'fetched'; projection: SourceConnectionProjection } | SourceConnectionResolution
> {
  assertControlPlaneOrigin(controlPlaneUrl);
  // Fail closed: an org-scoped pull never makes a wide unfiltered connections fetch.
  if (!orgId) throw new Error('source_connections_org_required');
  let response: Response;
  try {
    const query = new URLSearchParams({ orgId, tenantDeploymentId });
    if (protocol === 'capabilities') query.set('version', '2');
    response = await fetchImpl(
      `${controlPlaneUrl.replace(/\/$/, '')}/v1/deployments/${encodeURIComponent(runtimeDeploymentId)}/source-connections?${query.toString()}`,
      {
        headers: { authorization: `Bearer ${agentToken}` },
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      },
    );
  } catch {
    return { outcome: 'not_processed', reason: 'connection_fetch_failed' };
  }
  if (!response.ok) return { outcome: 'not_processed', reason: 'connection_fetch_failed' };
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { outcome: 'not_processed', reason: 'connection_response_invalid' };
  }
  const rawConnections =
    typeof body === 'object' && body !== null && !Array.isArray(body)
      ? (body as { connections?: unknown }).connections
      : undefined;
  const normalized = Array.isArray(rawConnections)
    ? rawConnections.map((connection) =>
        typeof connection === 'object' && connection !== null && !Array.isArray(connection)
          ? { ...emptyWebhookMetadata, ...connection }
          : connection,
      )
    : rawConnections;
  if (protocol === 'legacy') {
    if (
      typeof body !== 'object' ||
      body === null ||
      Array.isArray(body) ||
      Object.keys(body).length !== 1 ||
      !Object.hasOwn(body, 'connections')
    ) {
      return { outcome: 'not_processed', reason: 'connection_response_invalid' };
    }
    const connections = enclaveSourceConnectionProjectionSchema.array().safeParse(normalized);
    if (!connections.success) {
      return { outcome: 'not_processed', reason: 'connection_response_invalid' };
    }
    return { outcome: 'fetched', projection: { connections: connections.data, capabilities: [] } };
  }
  const projection = enclaveSourceConnectionsResponseSchema.safeParse(
    typeof body === 'object' && body !== null && !Array.isArray(body)
      ? { ...(body as Record<string, unknown>), connections: normalized }
      : body,
  );
  if (!projection.success)
    return { outcome: 'not_processed', reason: 'connection_response_invalid' };
  return { outcome: 'fetched', projection: projection.data };
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
  runtimeDeploymentId: string,
  tenantDeploymentId: string,
  agentToken: string,
  kind: string,
  orgId: string,
  crypto: EnclaveCrypto,
  fetchImpl: typeof globalThis.fetch,
): Promise<SourceConnectionResolution> {
  const fetched = await fetchSourceConnections(
    controlPlaneUrl,
    runtimeDeploymentId,
    tenantDeploymentId,
    agentToken,
    orgId,
    fetchImpl,
  );
  if (fetched.outcome !== 'fetched') return fetched;
  if (
    fetched.projection.connections.some(
      (connection) => connection.deploymentId !== tenantDeploymentId || connection.orgId !== orgId,
    )
  ) {
    return { outcome: 'not_processed', reason: 'connection_integrity_failed' };
  }
  const matches = fetched.projection.connections.filter((connection) => connection.kind === kind);
  if (matches.length === 0) return { outcome: 'missing' };
  if (matches.length !== 1) {
    return { outcome: 'not_processed', reason: 'connection_response_invalid' };
  }
  const match = matches[0];
  if (!match) return { outcome: 'not_processed', reason: 'connection_response_invalid' };

  return decryptSourceConnection(match, tenantDeploymentId, orgId, crypto);
}

export async function decryptSourceConnection(
  match: RawSourceConnection,
  tenantDeploymentId: string,
  orgId: string,
  crypto: EnclaveCrypto,
): Promise<SourceConnectionResolution> {
  if (
    match.deploymentId !== tenantDeploymentId ||
    match.orgId !== orgId ||
    match.attestationGeneration === null ||
    match.accessCiphertextSha256 === null ||
    match.accessCiphertextSha256 !== sha256Hex(match.encryptedAccessToken) ||
    (match.encryptedRefreshToken !== null &&
      match.encryptedRefreshToken !== undefined &&
      (match.refreshCiphertextSha256 === null ||
        match.refreshCiphertextSha256 === undefined ||
        match.refreshCiphertextSha256 !== sha256Hex(match.encryptedRefreshToken)))
  ) {
    return { outcome: 'not_processed', reason: 'connection_integrity_failed' };
  }
  try {
    return {
      outcome: 'connected',
      connection: {
        kind: match.kind,
        connectionId: match.connectionId,
        deploymentId: tenantDeploymentId,
        orgId,
        activationGeneration: match.activationGeneration,
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
        externalTenantId: match.externalTenantId ?? undefined,
        webhookRouteId: match.webhookRouteId,
        webhookRevision: match.webhookRevision,
        webhookRegistrationIds: match.webhookRegistrationIds,
        webhookExpiresAt: match.webhookExpiresAt,
        webhookStatus: match.webhookStatus,
        webhookLastOperation: match.webhookLastOperation,
        webhookLastAttemptedAt: match.webhookLastAttemptedAt,
        webhookLastSucceededAt: match.webhookLastSucceededAt,
        webhookLastDeliveryAt: match.webhookLastDeliveryAt,
        webhookProtocolCapture: match.webhookProtocolCapture,
        webhookProtocolCaptureExpiresAt: match.webhookProtocolCaptureExpiresAt,
        webhookFailureCode: match.webhookFailureCode,
        webhookCleanupRouteId: match.webhookCleanupRouteId,
        webhookCleanupExternalTenantId: match.webhookCleanupExternalTenantId,
        webhookCleanupRegistrationIds: match.webhookCleanupRegistrationIds,
        webhookCleanupExpiresAt: match.webhookCleanupExpiresAt,
      },
    };
  } catch {
    return { outcome: 'not_processed', reason: 'connection_decrypt_failed' };
  }
}
