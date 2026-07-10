import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { assertPublicIp, SsrfBlockedError } from './ssrf.js';

export type DnsLookup = (host: string) => Promise<{ address: string; family: number }[]>;
export type AddressGuard = (ip: string) => void;

export interface FetchedDocument {
  finalUrl: string;
  contentType: string;
  body: string;
}

export interface FetcherOptions {
  dnsLookup?: DnsLookup;
  guardAddress?: AddressGuard;
  maxBytes?: number;
  timeoutMs?: number;
  maxTotalMs?: number;
  maxRedirects?: number;
  userAgent?: string;
}

const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TOTAL_REQUEST_MS = 15_000;
const DEFAULT_MAX_REDIRECTS = 4;
const DEFAULT_USER_AGENT = 'FolkloreLinkPreview/1.0 (+https://folklore.build)';
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

type RequestOutcome =
  | { kind: 'redirect'; location: string }
  | { kind: 'document'; contentType: string; body: string };

async function defaultDnsLookup(host: string): Promise<{ address: string; family: number }[]> {
  const results = await lookup(host, { all: true, verbatim: true });
  return results.map((r) => ({ address: r.address, family: r.family }));
}

export class SsrfSafeFetcher {
  private readonly dnsLookup: DnsLookup;
  private readonly guardAddress: AddressGuard;
  private readonly maxBytes: number;
  private readonly timeoutMs: number;
  private readonly maxTotalMs: number;
  private readonly maxRedirects: number;
  private readonly userAgent: string;

  constructor(opts: FetcherOptions = {}) {
    this.dnsLookup = opts.dnsLookup ?? defaultDnsLookup;
    this.guardAddress = opts.guardAddress ?? assertPublicIp;
    this.maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxTotalMs = opts.maxTotalMs ?? MAX_TOTAL_REQUEST_MS;
    this.maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.userAgent = opts.userAgent ?? DEFAULT_USER_AGENT;
  }

  async fetch(rawUrl: string): Promise<FetchedDocument> {
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), this.maxTotalMs);
    try {
      return await this.fetchWithin(rawUrl, controller.signal);
    } finally {
      clearTimeout(deadline);
    }
  }

  async assertUrlPublic(rawUrl: string): Promise<void> {
    const url = this.parseAndVet(rawUrl);
    const literal = this.asIpLiteral(url.hostname);
    if (literal !== null) {
      this.guardAddress(literal);
      return;
    }
    await this.resolveGuarded(url.hostname);
  }

  private async fetchWithin(rawUrl: string, signal: AbortSignal): Promise<FetchedDocument> {
    let current = this.parseAndVet(rawUrl);
    for (let hop = 0; hop <= this.maxRedirects; hop++) {
      const address = await this.resolveGuarded(current.hostname);
      const outcome = await this.request(current, address, signal);
      if (outcome.kind === 'document') {
        return {
          finalUrl: current.toString(),
          contentType: outcome.contentType,
          body: outcome.body,
        };
      }
      current = this.parseAndVet(new URL(outcome.location, current).toString());
    }
    throw new SsrfBlockedError('too many redirects');
  }

  private asIpLiteral(hostname: string): string | null {
    const unbracketed =
      hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
    return isIP(unbracketed) !== 0 ? unbracketed : null;
  }

  private parseAndVet(rawUrl: string): URL {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new SsrfBlockedError('unparseable url');
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new SsrfBlockedError(`scheme ${url.protocol}`);
    }
    if (url.username || url.password) throw new SsrfBlockedError('embedded credentials');
    return url;
  }

  private async resolveGuarded(hostname: string): Promise<string> {
    const addresses = await this.dnsLookup(hostname);
    if (addresses.length === 0) throw new SsrfBlockedError(`no dns records for ${hostname}`);
    for (const { address } of addresses) this.guardAddress(address);
    return addresses[0]!.address;
  }

  private request(url: URL, address: string, signal: AbortSignal): Promise<RequestOutcome> {
    const isHttps = url.protocol === 'https:';
    const requestFn = isHttps ? httpsRequest : httpRequest;
    const port = url.port ? Number(url.port) : isHttps ? 443 : 80;

    return new Promise<RequestOutcome>((resolve, reject) => {
      const fail = (err: Error): void =>
        reject(signal.aborted ? new SsrfBlockedError('total request deadline exceeded') : err);
      const req = requestFn(
        {
          host: address,
          servername: isHttps ? url.hostname : undefined,
          port,
          path: `${url.pathname}${url.search}`,
          method: 'GET',
          headers: {
            Host: url.host,
            'User-Agent': this.userAgent,
            Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5',
            'Accept-Encoding': 'identity',
          },
          timeout: this.timeoutMs,
          signal,
        },
        (res) => this.consume(res, resolve, fail),
      );
      req.on('timeout', () => req.destroy(new SsrfBlockedError('request timeout')));
      req.on('error', fail);
      req.end();
    });
  }

  private consume(
    res: IncomingMessage,
    resolve: (o: RequestOutcome) => void,
    reject: (e: Error) => void,
  ): void {
    const status = res.statusCode ?? 0;
    if (REDIRECT_STATUSES.has(status)) {
      const location = res.headers['location'];
      res.resume();
      if (!location) return reject(new SsrfBlockedError(`redirect ${status} without location`));
      return resolve({ kind: 'redirect', location });
    }

    const contentType = String(res.headers['content-type'] ?? '');
    const chunks: Buffer[] = [];
    let size = 0;
    res.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > this.maxBytes) {
        res.destroy();
        resolve({ kind: 'document', contentType, body: Buffer.concat(chunks).toString('utf8') });
        return;
      }
      chunks.push(chunk);
    });
    res.on('end', () =>
      resolve({ kind: 'document', contentType, body: Buffer.concat(chunks).toString('utf8') }),
    );
    res.on('error', reject);
  }
}
