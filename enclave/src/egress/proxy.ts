import { EnvHttpProxyAgent, ProxyAgent, setGlobalDispatcher } from 'undici';
import { HttpsProxyAgent } from 'https-proxy-agent';

// Lock-step with the socat forwarder in enclave/entrypoint.sh and the vsock bridge in
// infra/src/enclave.ts (EGRESS_PROXY_VSOCK_PORT) — one literal, three files.
export const EGRESS_PROXY_PORT = 8002;
export const EGRESS_PROXY_URL = `http://localhost:${EGRESS_PROXY_PORT}`;

// Loopback callers — the AWS vsock proxy (:8000) and the inference vsock fallback (:8001) — must
// bypass the egress proxy or unseal and synthesis break. Production inference no longer takes that
// fallback after this lane: it keeps its real hostname and leaves through the CONNECT proxy, so
// `inference.phala.com` has to be in `egressHosts` (infra/src/enclave.ts).
export const LOOPBACK_NO_PROXY = 'localhost,127.0.0.1';

export interface EgressProxyConfig {
  httpProxy: string;
  httpsProxy: string;
  noProxy: string;
}

export function buildEgressProxyConfig(): EgressProxyConfig {
  return { httpProxy: EGRESS_PROXY_URL, httpsProxy: EGRESS_PROXY_URL, noProxy: LOOPBACK_NO_PROXY };
}

// Routes external fetch/undici SDKs through the CONNECT proxy while loopback bypasses it;
// AWS SDK v3 uses node:http (not undici), so its :8000 path is unaffected either way.
export function installGlobalEgressDispatcher(): void {
  const { httpProxy, httpsProxy, noProxy } = buildEgressProxyConfig();
  setGlobalDispatcher(new EnvHttpProxyAgent({ httpProxy, httpsProxy, noProxy }));
}

let externalProxyAgent: HttpsProxyAgent<string> | undefined;

// Slack's WebClient uses axios with `proxy: false`, so it must be handed an explicit agent.
export function externalHttpsProxyAgent(): HttpsProxyAgent<string> {
  return (externalProxyAgent ??= new HttpsProxyAgent(EGRESS_PROXY_URL));
}

// Per host only: a pool-wide cap lets idle sockets on one host starve requests to another.
const AWS_MAX_SOCKETS_PER_HOST = 16;
// Each idle tunnel holds a parent proxy thread until the far end closes it, so few are kept.
const AWS_MAX_FREE_SOCKETS_PER_HOST = 8;

export const AWS_PROXY_AGENT_OPTIONS = {
  keepAlive: true,
  maxSockets: AWS_MAX_SOCKETS_PER_HOST,
  maxFreeSockets: AWS_MAX_FREE_SOCKETS_PER_HOST,
} as const;

let awsProxyAgent: HttpsProxyAgent<string> | undefined;

// AWS SDK clients only: each request is signed on its own, so a pooled tunnel carries no tenant state.
export function awsHttpsProxyAgent(): HttpsProxyAgent<string> {
  return (awsProxyAgent ??= new HttpsProxyAgent(EGRESS_PROXY_URL, AWS_PROXY_AGENT_OPTIONS));
}

let exportProxyDispatcher: ProxyAgent | undefined;

// A fetch bound explicitly to the CONNECT egress proxy for the outbound wiki-export clients
// — belt-and-suspenders over the global dispatcher, so the export write can never dial
// a destination host directly and fails closed against the host allowlist.
export function proxiedExportFetch(): typeof globalThis.fetch {
  const dispatcher = (exportProxyDispatcher ??= new ProxyAgent(EGRESS_PROXY_URL));
  return ((input, init) =>
    globalThis.fetch(input, { ...init, dispatcher } as RequestInit)) as typeof globalThis.fetch;
}
