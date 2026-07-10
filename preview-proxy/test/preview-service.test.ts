import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { assertPublicIp, SsrfBlockedError } from '../src/ssrf.js';
import { SsrfSafeFetcher, type DnsLookup } from '../src/preview-fetch.js';
import { PreviewService } from '../src/preview-service.js';
import { RateLimiter } from '../src/rate-limiter.js';
import { handlePreviewRequest } from '../src/handler.js';

const OG_HTML = `<head>
  <meta property="og:title" content="Example Doc">
  <meta property="og:description" content="from the origin">
  <meta property="og:image" content="/cover.png">
</head>`;

let server: Server;
let port: number;

beforeAll(async () => {
  server = createServer((req, res) => {
    const path = req.url ?? '/';
    if (path === '/html') return end(res, 200, 'text/html', OG_HTML);
    if (path === '/redirect-external') return redirect(res, `http://site.test:${port}/html`);
    if (path === '/redirect-internal') return redirect(res, 'http://internal.test/secret');
    if (path === '/oversize') return end(res, 200, 'text/html', 'A'.repeat(50_000));
    if (path === '/oembed.json')
      return end(res, 200, 'application/json+oembed', JSON.stringify({ title: 'OEmbed Title' }));
    if (path === '/hang') return; // never responds — exercises the timeout
    if (path === '/drip') {
      res.writeHead(200, { 'content-type': 'text/html' });
      const timer = setInterval(() => res.write('a'), 40);
      req.on('close', () => clearInterval(timer));
      return;
    }
    return end(res, 404, 'text/plain', 'nope');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  port = typeof addr === 'object' && addr ? addr.port : 0;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const dnsLookup: DnsLookup = async (host) =>
  host === 'internal.test'
    ? [{ address: '10.0.0.1', family: 4 }]
    : [{ address: '127.0.0.1', family: 4 }];

// Allows the loopback test server but runs the real classifier on every other target,
// so redirect-to-internal is rejected by the same guard production uses.
const guardAddress = (ip: string): void => {
  if (ip === '127.0.0.1') return;
  assertPublicIp(ip);
};

function makeFetcher(overrides = {}): SsrfSafeFetcher {
  return new SsrfSafeFetcher({
    dnsLookup,
    guardAddress,
    timeoutMs: 400,
    maxBytes: 4096,
    ...overrides,
  });
}

function origin(host = 'site.test'): string {
  return `http://${host}:${port}`;
}

function end(res: import('node:http').ServerResponse, status: number, type: string, body: string) {
  res.writeHead(status, { 'content-type': type });
  res.end(body);
}

function redirect(res: import('node:http').ServerResponse, location: string) {
  res.writeHead(302, { location });
  res.end();
}

describe('SsrfSafeFetcher', () => {
  it('fetches and returns the origin document', async () => {
    const doc = await makeFetcher().fetch(`${origin()}/html`);
    expect(doc.contentType).toContain('text/html');
    expect(doc.body).toContain('Example Doc');
  });

  it('follows a redirect to another public target', async () => {
    const doc = await makeFetcher().fetch(`${origin()}/redirect-external`);
    expect(doc.body).toContain('Example Doc');
  });

  it('rejects a redirect to an internal address', async () => {
    await expect(makeFetcher().fetch(`${origin()}/redirect-internal`)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('rejects a direct internal target at resolve time', async () => {
    await expect(makeFetcher().fetch('http://internal.test/secret')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('rejects a non-http scheme', async () => {
    await expect(makeFetcher().fetch('ftp://site.test/x')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('rejects embedded credentials', async () => {
    await expect(
      makeFetcher().fetch(`http://user:pass@site.test:${port}/html`),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('caps the response body at maxBytes', async () => {
    const doc = await makeFetcher({ maxBytes: 1000 }).fetch(`${origin()}/oversize`);
    expect(doc.body.length).toBeLessThanOrEqual(1000);
  });

  it('times out a hanging response', async () => {
    await expect(makeFetcher({ timeoutMs: 150 }).fetch(`${origin()}/hang`)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('aborts a slow-drip response at the total deadline', async () => {
    await expect(
      makeFetcher({ timeoutMs: 1000, maxTotalMs: 200 }).fetch(`${origin()}/drip`),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('rejects a redirect loop past maxRedirects', async () => {
    await expect(
      makeFetcher({ maxRedirects: 0 }).fetch(`${origin()}/redirect-external`),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});

describe('PreviewService', () => {
  it('produces a preview from OG tags', async () => {
    const preview = await new PreviewService(makeFetcher()).preview(`${origin()}/html`);
    expect(preview?.title).toBe('Example Doc');
    expect(preview?.imageUrl).toBe(`${origin()}/cover.png`);
  });

  it('returns null on an SSRF-blocked target', async () => {
    const preview = await new PreviewService(makeFetcher()).preview('http://internal.test/x');
    expect(preview).toBeNull();
  });

  it('parses a direct oEmbed json response', async () => {
    const preview = await new PreviewService(makeFetcher()).preview(`${origin()}/oembed.json`);
    expect(preview?.title).toBe('OEmbed Title');
  });
});

describe('handlePreviewRequest', () => {
  const service = new PreviewService(makeFetcher());

  it('400s on invalid json', async () => {
    const reply = await handlePreviewRequest('{', service, new RateLimiter());
    expect(reply.status).toBe(400);
  });

  it('400s on a non-url', async () => {
    const reply = await handlePreviewRequest('{"url":"not a url"}', service, new RateLimiter());
    expect(reply.status).toBe(400);
  });

  it('200s with a preview', async () => {
    const reply = await handlePreviewRequest(
      JSON.stringify({ url: `${origin()}/html` }),
      service,
      new RateLimiter(),
    );
    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body).preview.title).toBe('Example Doc');
  });

  it('429s past the rate limit', async () => {
    const limiter = new RateLimiter(1);
    const body = JSON.stringify({ url: `${origin()}/html` });
    await handlePreviewRequest(body, service, limiter);
    const second = await handlePreviewRequest(body, service, limiter);
    expect(second.status).toBe(429);
  });
});
