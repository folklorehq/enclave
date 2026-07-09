import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';

type FetchHandler = (req: Request) => Response | Promise<Response>;

export class BoxServer {
  private readonly app: Hono;
  private readonly apiReady: boolean;

  constructor(
    private readonly api?: FetchHandler,
    private readonly port = 3000,
  ) {
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

    if (this.api) {
      const api = this.api;
      // ADL #31: every /api/* request runs in-process over content decrypted only
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

  start(): void {
    serve({ fetch: this.app.fetch, port: this.port });
    console.log('box server listening', {
      port: this.port,
      api: this.apiReady ? 'mounted' : 'unavailable',
    });
  }
}
