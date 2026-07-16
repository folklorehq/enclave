import { EnvHttpProxyAgent, ProxyAgent, setGlobalDispatcher } from 'undici';
import { HttpsProxyAgent } from 'https-proxy-agent';

// Lock-step with the socat forwarder in enclave/entrypoint.sh and the vsock bridge in
// infra/src/enclave.ts (EGRESS_PROXY_VSOCK_PORT) — one literal, three files (ADL #42).
export const EGRESS_PROXY_PORT = 8002;
const PROXY_URL = `http://localhost:${EGRESS_PROXY_PORT}`;

// AWS (:8000) and inference (:8001) reach the parent over their own vsock proxies, so
// loopback must bypass the egress proxy or unseal/synthesis break.
export const LOOPBACK_NO_PROXY = 'localhost,127.0.0.1';

export interface EgressProxyConfig {
  httpProxy: string;
  httpsProxy: string;
  noProxy: string;
}

export function buildEgressProxyConfig(): EgressProxyConfig {
  return { httpProxy: PROXY_URL, httpsProxy: PROXY_URL, noProxy: LOOPBACK_NO_PROXY };
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
  return (externalProxyAgent ??= new HttpsProxyAgent(PROXY_URL));
}

let exportProxyDispatcher: ProxyAgent | undefined;

// A fetch bound explicitly to the CONNECT egress proxy for the outbound wiki-export clients
// (ADL #65) — belt-and-suspenders over the global dispatcher, so the export write can never dial
// a destination host directly and fails closed against the host allowlist.
export function proxiedExportFetch(): typeof globalThis.fetch {
  const dispatcher = (exportProxyDispatcher ??= new ProxyAgent(PROXY_URL));
  return ((input, init) =>
    globalThis.fetch(input, { ...init, dispatcher } as RequestInit)) as typeof globalThis.fetch;
}
