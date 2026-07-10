import { describe, expect, it } from 'vitest';
import { parseHtmlPreview, parseOembedPreview, type UrlGuard } from '../src/og-parse.js';
import { SsrfSafeFetcher, type DnsLookup } from '../src/preview-fetch.js';
import { assertPublicIp } from '../src/ssrf.js';

const BASE = 'https://example.com/article';

const dnsLookup: DnsLookup = async (host) =>
  host === 'internal.example.com'
    ? [{ address: '10.0.0.5', family: 4 }]
    : [{ address: '93.184.216.34', family: 4 }];

const guard: UrlGuard = (url) =>
  new SsrfSafeFetcher({ dnsLookup, guardAddress: assertPublicIp }).assertUrlPublic(url).then(
    () => true,
    () => false,
  );

describe('parseHtmlPreview', () => {
  it('extracts OG tags and resolves relative image + discovers oembed', async () => {
    const html = `
      <html><head>
        <meta property="og:title" content="Hello &amp; World" />
        <meta property="og:description" content="A great read" />
        <meta property="og:image" content="/img/cover.png" />
        <link rel="icon" href="/favicon.png" />
        <link rel="alternate" type="application/json+oembed" href="https://example.com/oembed?u=1" />
      </head></html>`;
    const { preview, oembedHref } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.title).toBe('Hello & World');
    expect(preview.description).toBe('A great read');
    expect(preview.imageUrl).toBe('https://example.com/img/cover.png');
    expect(preview.faviconUrl).toBe('https://example.com/favicon.png');
    expect(oembedHref).toBe('https://example.com/oembed?u=1');
  });

  it('falls back to <title> and twitter tags', async () => {
    const html = `<head><title>Just A Title</title>
      <meta name="twitter:description" content="tw desc"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.title).toBe('Just A Title');
    expect(preview.description).toBe('tw desc');
  });

  it('defaults favicon to origin /favicon.ico', async () => {
    const { preview } = await parseHtmlPreview('<head></head>', BASE, guard);
    expect(preview.faviconUrl).toBe('https://example.com/favicon.ico');
  });

  it('drops a non-http image url (javascript/data)', async () => {
    const html = `<head><meta property="og:image" content="javascript:alert(1)"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.imageUrl).toBeUndefined();
  });

  it('bounds an over-long title', async () => {
    const long = 'x'.repeat(5000);
    const html = `<head><meta property="og:title" content="${long}"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.title!.length).toBeLessThanOrEqual(300);
  });
});

describe('parseHtmlPreview — returned-url SSRF guard', () => {
  const literalHosts = ['169.254.169.254', '127.0.0.1', '10.0.0.1'];
  for (const host of literalHosts) {
    it(`drops an og:image at ${host}`, async () => {
      const html = `<head><meta property="og:image" content="http://${host}/pixel.png"></head>`;
      const { preview } = await parseHtmlPreview(html, BASE, guard);
      expect(preview.imageUrl).toBeUndefined();
    });
  }

  it('drops an og:image at the IPv6 loopback', async () => {
    const html = `<head><meta property="og:image" content="http://[::1]/pixel.png"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.imageUrl).toBeUndefined();
  });

  it('drops an og:image whose hostname resolves to a private IP', async () => {
    const html = `<head><meta property="og:image" content="http://internal.example.com/pixel.png"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.imageUrl).toBeUndefined();
  });

  it('drops a private-IP favicon and falls back to the public origin default', async () => {
    const html = `<head><link rel="icon" href="http://169.254.169.254/favicon.ico"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.faviconUrl).toBe('https://example.com/favicon.ico');
  });

  it('keeps a normal public image url', async () => {
    const html = `<head><meta property="og:image" content="https://cdn.example.com/cover.png"></head>`;
    const { preview } = await parseHtmlPreview(html, BASE, guard);
    expect(preview.imageUrl).toBe('https://cdn.example.com/cover.png');
  });
});

describe('parseOembedPreview', () => {
  it('maps title + thumbnail_url', async () => {
    const preview = await parseOembedPreview(
      { title: 'Video', thumbnail_url: 'https://cdn.example.com/t.jpg', author_name: 'Ada' },
      BASE,
      guard,
    );
    expect(preview.title).toBe('Video');
    expect(preview.imageUrl).toBe('https://cdn.example.com/t.jpg');
    expect(preview.description).toBe('Ada');
  });

  it('drops a thumbnail_url at a private IP', async () => {
    const preview = await parseOembedPreview(
      { title: 'Video', thumbnail_url: 'http://169.254.169.254/t.jpg' },
      BASE,
      guard,
    );
    expect(preview.title).toBe('Video');
    expect(preview.imageUrl).toBeUndefined();
  });

  it('ignores a non-object', async () => {
    expect(await parseOembedPreview('nope', BASE, guard)).toEqual({});
  });
});
