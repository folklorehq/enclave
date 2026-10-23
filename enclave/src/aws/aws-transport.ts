import { fromInstanceMetadata } from '@smithy/credential-provider-imds';
import type { HttpsProxyAgent } from 'https-proxy-agent';
import { awsHttpsProxyAgent } from '../egress/proxy.js';

const DEV_ENDPOINT_PORT_VAR = 'VSOCK_KMS_PROXY_PORT';
const DEV_NODE_ENV = 'development';
// Three times the longest SQS long poll (20 s), so only a stalled socket is cut, never a quiet one.
export const AWS_SOCKET_IDLE_TIMEOUT_MS = 60_000;
export const AWS_CONNECTION_TIMEOUT_MS = 10_000;

type AwsCredentialIdentityProvider = ReturnType<typeof fromInstanceMetadata>;
type AwsCredentials = Awaited<ReturnType<AwsCredentialIdentityProvider>>;

// The SDK default is 1000 ms and 0 retries, which the socat vsock relay outran under load.
export const IMDS_TIMEOUT_MS = 3_000;
export const IMDS_MAX_RETRIES = 3;

export interface AwsClientTransport {
  credentials: AwsCredentialIdentityProvider;
  requestHandler: {
    httpsAgent: HttpsProxyAgent<string>;
    connectionTimeout: number;
    socketTimeout: number;
  };
}

export interface DevEndpointTransport {
  endpoint: string;
}

// entrypoint.sh pins NODE_ENV=production after sourcing the parent-supplied env file, so gating on
// it — the same way devMasterKeySealers does — keeps the parent from reinstating the loopback
// endpoint, whose SNI mismatch is the outage this transport exists to remove.
function devEndpoint(): DevEndpointTransport | undefined {
  if (process.env['NODE_ENV'] !== DEV_NODE_ENV) return undefined;
  const port = process.env[DEV_ENDPOINT_PORT_VAR];
  return port ? { endpoint: `https://localhost:${port}` } : undefined;
}

const EXPIRED_MARGIN_MS = 60_000;

function isUsable(credentials: AwsCredentials): boolean {
  return (
    credentials.expiration === undefined ||
    credentials.expiration.getTime() - Date.now() > EXPIRED_MARGIN_MS
  );
}

// The raw IMDS provider refetches per call; this reuses one result and one in-flight fetch.
function memoizeUntilExpiry(
  provider: AwsCredentialIdentityProvider,
): AwsCredentialIdentityProvider {
  let current: AwsCredentials | undefined;
  let inflight: Promise<AwsCredentials> | undefined;
  return async () => {
    if (current && isUsable(current)) return current;
    inflight ??= provider().finally(() => {
      inflight = undefined;
    });
    current = await inflight;
    return current;
  };
}

let sharedCredentials: AwsCredentialIdentityProvider | undefined;

export function awsCredentials(): AwsCredentialIdentityProvider {
  sharedCredentials ??= memoizeUntilExpiry(
    fromInstanceMetadata({ timeout: IMDS_TIMEOUT_MS, maxRetries: IMDS_MAX_RETRIES }),
  );
  return sharedCredentials;
}

// Tests need a fresh memo per fake IMDS server.
export function resetAwsCredentialsForTest(): void {
  sharedCredentials = undefined;
}

// SDK v3 uses node:http, not undici, so the global egress dispatcher misses it — hand the agent to
// the client, which builds its own NodeHttpHandler from these options (HttpHandlerUserInput).
export function awsClientTransport(): AwsClientTransport | DevEndpointTransport {
  return (
    devEndpoint() ?? {
      credentials: awsCredentials(),
      requestHandler: {
        httpsAgent: awsHttpsProxyAgent(),
        connectionTimeout: AWS_CONNECTION_TIMEOUT_MS,
        socketTimeout: AWS_SOCKET_IDLE_TIMEOUT_MS,
      },
    }
  );
}
