import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { handlePreviewRequest } from './handler.js';
import { PreviewService } from './preview-service.js';
import { SsrfSafeFetcher } from './preview-fetch.js';
import { RateLimiter } from './rate-limiter.js';

const HOST = process.env['PREVIEW_PROXY_HOST'] ?? '127.0.0.1';
const PORT = Number(process.env['PREVIEW_PROXY_PORT'] ?? 8100);
const MAX_REQUEST_BYTES = 8 * 1024;
const PREVIEW_PATH = '/preview';

export class PreviewProxyServer {
  private readonly server;

  constructor(
    private readonly service: PreviewService,
    private readonly rateLimiter: RateLimiter,
  ) {
    this.server = createServer((req, res) => void this.route(req, res));
  }

  listen(port: number, host: string): void {
    this.server.listen(port, host, () => console.log('preview-proxy listening', { host, port }));
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === 'GET' && req.url === '/health') return this.send(res, 200, '{"ok":true}');
    if (req.method !== 'POST' || req.url !== PREVIEW_PATH) return this.send(res, 404, '{}');

    let body: string;
    try {
      body = await this.readBody(req);
    } catch {
      return this.send(res, 413, JSON.stringify({ error: 'body too large' }));
    }

    const reply = await handlePreviewRequest(body, this.service, this.rateLimiter);
    this.send(res, reply.status, reply.body);
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_REQUEST_BYTES) {
          req.destroy();
          reject(new Error('body too large'));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  private send(res: ServerResponse, status: number, body: string): void {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(body);
  }
}

const server = new PreviewProxyServer(new PreviewService(new SsrfSafeFetcher()), new RateLimiter());
server.listen(PORT, HOST);
