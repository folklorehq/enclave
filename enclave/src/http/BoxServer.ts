import { once } from 'node:events';
import { Server, type IncomingMessage } from 'node:http';
import { createConnection, Socket, type AddressInfo } from 'node:net';
import type { Duplex } from 'node:stream';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { COLLAB_DEFAULT_PORT, COLLAB_WS_PATH, MAX_TCP_PORT } from '@folklore/contracts';

type FetchHandler = (req: Request) => Response | Promise<Response>;

export interface BoxServerOptions {
  readonly httpPort?: number;
  readonly collabPort?: number;
}

const DEFAULT_HTTP_PORT = 3000;
const MIN_TCP_PORT = 1;
const LOOPBACK_ADDRESS = '127.0.0.1';
const WEBSOCKET_UPGRADE = 'websocket';
const UPGRADE_REQUIRED = 'HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\n\r\n';
const COLLAB_UNAVAILABLE = 'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n';
// An upgrade allocates a loopback socket before the handshake authenticates, so cap the fan-out.
const MAX_ACTIVE_COLLAB_PROXIES = 256;
const REFUSAL_NOTICE_INTERVAL_MS = 60_000;
const DIAL_TIMEOUT_MS = 5_000;
// Shutdown must never outlast an editor holding a socket open — the index save runs after it.
const CLOSE_TIMEOUT_MS = 5_000;
const REFUSED_UNCONFIGURED = 'unconfigured';
const REFUSED_CAPACITY = 'capacity';
const REFUSED_UPSTREAM = 'upstream_unreachable';

export class BoxServer {
  private readonly app: Hono;
  private readonly apiReady: boolean;
  private readonly httpPort: number;
  // Absent when the configured port is unusable: collab degrades, the enclave still boots.
  private readonly collabPort?: number;
  private server?: Server;
  private activeCollabProxies = 0;
  // Upgraded sockets are detached from the server's connection tracking, so `close()` cannot see
  // them: without this set a single open editor would block shutdown past the tenant index save.
  private readonly relayedClients = new Set<Socket>();
  private readonly lastRefusalNoticeAt = new Map<string, number>();

  constructor(
    private readonly api?: FetchHandler,
    options: BoxServerOptions = {},
  ) {
    this.httpPort = options.httpPort ?? DEFAULT_HTTP_PORT;
    this.collabPort = this.usableCollabPort(options.collabPort ?? COLLAB_DEFAULT_PORT);
    this.apiReady = Boolean(this.api);
    this.app = new Hono();

    // Degraded when the API failed to compose at boot: report it so the outage is
    // visible rather than masquerading as a healthy static-only instance.
    this.app.get('/health', (c) =>
      c.json(
        { ok: this.apiReady, api: this.apiReady ? 'ok' : 'unavailable' },
        this.apiReady ? 200 : 503,
      ),
    );

    // Without this a non-upgrade GET would fall through to the catch-all and answer 200 index.html.
    this.app.all(COLLAB_WS_PATH, (c) => c.text('upgrade required', 426));

    if (this.api) {
      const api = this.api;
      // every /api/* request runs in-process over content decrypted only
      // inside this enclave — no decrypted body is ever proxied to the parent.
      this.app.all('/api/*', (c) => api(c.req.raw));
    } else {
      // Never let /api/* fall through to the SPA catch-all: callers expect JSON and
      // a 200 index.html would hide the outage behind a healthy-looking response.
      this.app.all('/api/*', (c) => c.json({ error: 'api_unavailable' }, 503));
    }

    this.app.use('/*', serveStatic({ root: './dist/box' }));
    this.app.get('/*', serveStatic({ path: './dist/box/index.html' }));
  }

  get fetch(): FetchHandler {
    return this.app.fetch;
  }

  // Live relayed-collab count: the activity signal the idle/self-stop path needs.
  get activeCollabConnections(): number {
    return this.activeCollabProxies;
  }

  get address(): AddressInfo | null {
    const address = this.server?.address();
    return address && typeof address !== 'string' ? address : null;
  }

  async start(): Promise<void> {
    const server = serve({ fetch: this.app.fetch, port: this.httpPort });
    // Narrowing off the adapter's union restores real listener typing — and http/2 has no upgrade.
    if (!(server instanceof Server)) {
      throw new Error('refusing to start: expected an http/1.1 server');
    }
    server.on('upgrade', (req, client, head) => this.handleUpgrade(req, client, head));
    this.server = server;
    if (!server.listening) await once(server, 'listening');
    console.log('box server listening', {
      port: this.httpPort,
      api: this.apiReady ? 'mounted' : 'unavailable',
      collab: this.collabPort === undefined ? 'disabled' : 'proxied',
    });
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = undefined;
    // A relayed socket never closes on its own, and the tenant index save runs after this resolves.
    for (const client of this.relayedClients) client.destroy();
    this.relayedClients.clear();
    server.closeAllConnections();
    await Promise.race([
      new Promise<void>((resolve) => server.close(() => resolve())),
      new Promise<void>((resolve) => {
        setTimeout(resolve, CLOSE_TIMEOUT_MS).unref();
      }),
    ]);
  }

  private usableCollabPort(port: number): number | undefined {
    const usable =
      Number.isInteger(port) &&
      port >= MIN_TCP_PORT &&
      port <= MAX_TCP_PORT &&
      port !== this.httpPort;
    return usable ? port : undefined;
  }

  // #67: the collab WS stays loopback-bound, so its upgrade is relayed here, not on a second listener.
  private handleUpgrade(req: IncomingMessage, client: Duplex, head: Buffer): void {
    if (!(client instanceof Socket)) return void client.destroy();
    if (client.destroyed) return;
    client.on('error', () => client.destroy());
    if (!this.isCollabUpgrade(req)) return this.refuse(client, UPGRADE_REQUIRED);
    const collabPort = this.collabPort;
    if (!this.apiReady || collabPort === undefined) {
      return this.refuse(client, COLLAB_UNAVAILABLE, REFUSED_UNCONFIGURED);
    }
    if (this.activeCollabProxies >= MAX_ACTIVE_COLLAB_PROXIES) {
      return this.refuse(client, COLLAB_UNAVAILABLE, REFUSED_CAPACITY);
    }
    this.dialCollab(req, client, head, collabPort);
  }

  private isCollabUpgrade(req: IncomingMessage): boolean {
    const path = req.url?.split('?')[0] ?? '';
    return path === COLLAB_WS_PATH && req.headers.upgrade?.toLowerCase() === WEBSOCKET_UPGRADE;
  }

  private dialCollab(req: IncomingMessage, client: Socket, head: Buffer, port: number): void {
    let relaying = false;
    const upstream = createConnection(port, LOOPBACK_ADDRESS, () => {
      relaying = true;
      clearTimeout(dialTimer);
      this.relay(req, client, upstream, head);
    });
    this.activeCollabProxies += 1;
    this.relayedClients.add(client);
    // A dial that neither connects nor errors would otherwise hold its capacity slot forever.
    const dialTimer = setTimeout(() => upstream.destroy(), DIAL_TIMEOUT_MS);
    dialTimer.unref();
    const release = this.releaseOnce(client, () => clearTimeout(dialTimer));
    // destroySoon so a queued close frame still flushes, but the fd and its slot are always freed.
    client.once('close', () => {
      release();
      upstream.destroySoon();
    });
    upstream.once('close', () => {
      release();
      client.destroySoon();
    });
    client.on('error', () => upstream.destroy());
    upstream.on('error', () => {
      if (relaying) return void client.destroy();
      this.refuse(client, COLLAB_UNAVAILABLE, REFUSED_UPSTREAM);
    });
  }

  private releaseOnce(client: Socket, onRelease: () => void): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.activeCollabProxies -= 1;
      this.relayedClients.delete(client);
      onRelease();
    };
  }

  // Verbatim in Node's own latin1 header decoding — the upstream handshake authorizes on these.
  private relay(req: IncomingMessage, client: Socket, upstream: Socket, head: Buffer): void {
    upstream.setNoDelay(true);
    upstream.write(this.serializeUpgradeRequest(req), 'latin1');
    if (head.length > 0) upstream.write(head);
    client.pipe(upstream);
    upstream.pipe(client);
  }

  private serializeUpgradeRequest(req: IncomingMessage): string {
    const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
    const headers = req.rawHeaders;
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const name = headers[i];
      const value = headers[i + 1];
      if (name !== undefined && value !== undefined) lines.push(`${name}: ${value}`);
    }
    return `${lines.join('\r\n')}\r\n\r\n`;
  }

  private refuse(client: Socket, response: string, reason?: string): void {
    if (reason) this.reportRefusal(reason);
    if (client.destroyed) return;
    client.end(response);
    client.destroySoon();
  }

  // Content-free + throttled per reason: a silently wedged collab path is exactly the
  // failure this proxy exists to end, so it must never fail quietly itself.
  private reportRefusal(reason: string): void {
    const now = Date.now();
    const last = this.lastRefusalNoticeAt.get(reason) ?? 0;
    if (now - last < REFUSAL_NOTICE_INTERVAL_MS) return;
    this.lastRefusalNoticeAt.set(reason, now);
    console.error('collab upgrade refused', { reason, active: this.activeCollabProxies });
  }
}
