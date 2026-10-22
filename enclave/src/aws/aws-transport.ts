import type { HttpsProxyAgent } from 'https-proxy-agent';
import { awsHttpsProxyAgent } from '../egress/proxy.js';

const DEV_ENDPOINT_PORT_VAR = 'VSOCK_KMS_PROXY_PORT';
const DEV_NODE_ENV = 'development';
// Three times the longest SQS long poll (20 s), so only a stalled socket is cut, never a quiet one.
export const AWS_SOCKET_IDLE_TIMEOUT_MS = 60_000;
export const AWS_CONNECTION_TIMEOUT_MS = 10_000;

export interface AwsClientTransport {
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

// SDK v3 uses node:http, not undici, so the global egress dispatcher misses it — hand the agent to
// the client, which builds its own NodeHttpHandler from these options (HttpHandlerUserInput).
export function awsClientTransport(): AwsClientTransport | DevEndpointTransport {
  return (
    devEndpoint() ?? {
      requestHandler: {
        httpsAgent: awsHttpsProxyAgent(),
        connectionTimeout: AWS_CONNECTION_TIMEOUT_MS,
        socketTimeout: AWS_SOCKET_IDLE_TIMEOUT_MS,
      },
    }
  );
}
