import type { HttpsProxyAgent } from 'https-proxy-agent';
import { externalHttpsProxyAgent } from '../egress/proxy.js';

const DEV_ENDPOINT_PORT_VAR = 'VSOCK_KMS_PROXY_PORT';
const DEV_NODE_ENV = 'development';

export interface AwsClientTransport {
  requestHandler: { httpsAgent: HttpsProxyAgent<string> };
}

export interface AwsV2ClientTransport {
  httpOptions: { agent: HttpsProxyAgent<string> };
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
  return devEndpoint() ?? { requestHandler: { httpsAgent: externalHttpsProxyAgent() } };
}

// aws-sdk v2's only proxy seam is httpOptions.agent; keeping the real hostname is what makes SNI
// match the AWS cert, so the parent EC2 terminating the CONNECT tunnel cannot MITM the session.
export function awsV2ClientTransport(): AwsV2ClientTransport | DevEndpointTransport {
  return devEndpoint() ?? { httpOptions: { agent: externalHttpsProxyAgent() } };
}
