import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';

export class BoxServer {
  private readonly app: Hono;

  constructor(private readonly port = 3000) {
    this.app = new Hono();
    this.app.get('/health', (c) => c.json({ ok: true }));
    this.app.use('/*', serveStatic({ root: './dist/box' }));
    this.app.get('/*', serveStatic({ path: './dist/box/index.html' }));
  }

  start(): void {
    serve({ fetch: this.app.fetch, port: this.port });
    console.log('box server listening', { port: this.port });
  }
}
