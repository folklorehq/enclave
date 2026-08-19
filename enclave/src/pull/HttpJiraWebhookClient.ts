import { createHash, randomBytes } from 'node:crypto';
import { ProxyAgent } from 'undici';
import {
  assertPublicAddressSet,
  ProviderEgressError,
  ProviderRejectedError,
  resolvePublicAddresses,
  type ProviderTokenFetchOptions,
} from '../egress/provider-token-fetch.js';
import { EGRESS_PROXY_PORT } from '../egress/proxy.js';

const JIRA_GATEWAY_ORIGIN = 'https://api.atlassian.com';
const JIRA_GATEWAY_HOST = 'api.atlassian.com';
const JIRA_WEBHOOK_PATH = '/rest/api/3/webhook';
const JIRA_WEBHOOK_URL_PATTERN =
  /^https:\/\/webhooks\.folklorehq\.com\/ingest\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/jira\?route=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DECIMAL_ID_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_URL_BYTES = 2 * 1024;
const MAX_JQL_BYTES = 8 * 1024;
const MAX_EVENT_BYTES = 256;
const MAX_EVENTS = 32;
const MAX_REGISTRATION_IDS = 16;
const MAX_ID_DIGITS = 16;
const MAX_LIST_PAGES = 8;
const MAX_LIST_ITEMS = 256;
const LIST_PAGE_SIZE = 100;
const WEBHOOK_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const EXPECTED_EVENTS = [
  'jira:issue_created',
  'jira:issue_updated',
  'comment_created',
  'comment_updated',
] as const;

export interface JiraWebhookListInput {
  cloudId: string;
  accessToken: string;
}

export interface JiraWebhookRegistrationInput extends JiraWebhookListInput {
  webhookUrl: string;
}

export interface JiraWebhookIdsInput extends JiraWebhookListInput {
  registrationIds: readonly string[];
}

export interface JiraWebhookRegistration {
  id: string;
  url: string;
  events: readonly string[];
  jqlFilter: string;
  expiresAt: string;
}

export interface JiraWebhookClientPort {
  list(input: JiraWebhookListInput): Promise<JiraWebhookRegistration[]>;
  register(input: JiraWebhookRegistrationInput): Promise<{
    registrationIds: string[];
    expiresAt: string;
  }>;
  refresh(input: JiraWebhookIdsInput): Promise<{ expiresAt: string }>;
  delete(input: JiraWebhookIdsInput): Promise<void>;
}

export interface JiraWebhookClientOptions extends Pick<
  ProviderTokenFetchOptions,
  | 'fetchImpl'
  | 'resolve'
  | 'assertProxyResolution'
  | 'maxRequestBytes'
  | 'maxResponseBytes'
  | 'timeoutMs'
> {
  clock?: () => Date;
}

interface JiraWebhookPage {
  values: JiraWebhookRegistration[];
  isLast: boolean;
  startAt: number;
  total: number | null;
}

interface JiraWebhookRequest {
  cloudId: string;
  accessToken: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  suffix?: string;
  body?: unknown;
  expectedStatus: number;
  parseJson: boolean;
}

/** Performs only the fixed Jira dynamic-webhook protocol through the enclave egress proxy. */
export class HttpJiraWebhookClient implements JiraWebhookClientPort {
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly resolve: (hostname: string) => Promise<readonly string[]>;
  private readonly assertProxyResolution: (
    hostname: string,
    addresses: readonly string[],
  ) => Promise<void>;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private readonly timeoutMs: number;
  private readonly clock: () => Date;

  constructor(options: JiraWebhookClientOptions) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.resolve = options.resolve ?? resolvePublicAddresses;
    this.assertProxyResolution = options.assertProxyResolution;
    this.maxRequestBytes = options.maxRequestBytes ?? MAX_REQUEST_BYTES;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.clock = options.clock ?? (() => new Date());
  }

  async list(input: JiraWebhookListInput): Promise<JiraWebhookRegistration[]> {
    const cloudId = this.normalizeCloudId(input.cloudId);
    const accessToken = this.normalizeAccessToken(input.accessToken);
    const registrations: JiraWebhookRegistration[] = [];
    let startAt = 0;

    for (let pageNumber = 0; pageNumber < MAX_LIST_PAGES; pageNumber += 1) {
      const page = this.parseListPage(
        await this.request({
          cloudId,
          accessToken,
          method: 'GET',
          suffix: `?startAt=${startAt}&maxResults=${LIST_PAGE_SIZE}`,
          expectedStatus: 200,
          parseJson: true,
        }),
      );
      if (registrations.length + page.values.length > MAX_LIST_ITEMS) {
        throw new ProviderEgressError();
      }
      registrations.push(...page.values);
      if (
        page.isLast ||
        page.values.length === 0 ||
        (page.total !== null && startAt + page.values.length >= page.total)
      ) {
        return registrations;
      }
      const nextStartAt = page.startAt + page.values.length;
      if (!Number.isSafeInteger(nextStartAt) || nextStartAt <= startAt) {
        throw new JiraWebhookResponseError();
      }
      startAt = nextStartAt;
    }
    throw new ProviderEgressError();
  }

  async register(input: JiraWebhookRegistrationInput): Promise<{
    registrationIds: string[];
    expiresAt: string;
  }> {
    const cloudId = this.normalizeCloudId(input.cloudId);
    const accessToken = this.normalizeAccessToken(input.accessToken);
    this.validateWebhookUrl(input.webhookUrl);
    const result = this.asRecord(
      await this.request({
        cloudId,
        accessToken,
        method: 'POST',
        body: {
          url: input.webhookUrl,
          webhooks: [{ events: [...EXPECTED_EVENTS], jqlFilter: '' }],
        },
        expectedStatus: 200,
        parseJson: true,
      }),
    );
    const results = result['webhookRegistrationResult'];
    if (!Array.isArray(results) || results.length !== 1 || !this.isRecord(results[0])) {
      throw new JiraWebhookResponseError();
    }
    const registration = results[0];
    if (registration['errors'] !== undefined) {
      if (!Array.isArray(registration['errors']) || registration['errors'].length !== 0) {
        throw new JiraWebhookResponseError();
      }
    }
    const id = this.registrationId(registration['createdWebhookId']);
    return { registrationIds: [id], expiresAt: this.futureLifetime() };
  }

  async refresh(input: JiraWebhookIdsInput): Promise<{ expiresAt: string }> {
    const cloudId = this.normalizeCloudId(input.cloudId);
    const accessToken = this.normalizeAccessToken(input.accessToken);
    const registrationIds = this.registrationIds(input.registrationIds);
    const result = this.asRecord(
      await this.request({
        cloudId,
        accessToken,
        method: 'PUT',
        suffix: '/refresh',
        body: { webhookIds: registrationIds.map(Number) },
        expectedStatus: 200,
        parseJson: true,
      }),
    );
    return { expiresAt: this.futureExpiration(result['expirationDate']) };
  }

  async delete(input: JiraWebhookIdsInput): Promise<void> {
    const cloudId = this.normalizeCloudId(input.cloudId);
    const accessToken = this.normalizeAccessToken(input.accessToken);
    const registrationIds = this.registrationIds(input.registrationIds);
    await this.request({
      cloudId,
      accessToken,
      method: 'DELETE',
      body: { webhookIds: registrationIds.map(Number) },
      expectedStatus: 202,
      parseJson: false,
    });
  }

  private async request(request: JiraWebhookRequest): Promise<unknown> {
    const endpoint = this.endpoint(this.normalizeCloudId(request.cloudId), request.suffix ?? '');
    const body = request.body === undefined ? undefined : JSON.stringify(request.body);
    if (body && Buffer.byteLength(body, 'utf8') > this.maxRequestBytes) {
      throw new ProviderEgressError();
    }
    const addresses = await this.providerAddresses();
    const bindingNonce = randomBytes(16).toString('hex');
    const proxy = new ProxyAgent({
      uri: `http://localhost:${EGRESS_PROXY_PORT}`,
      headers: {
        'x-folklore-egress-address-set-sha256': this.addressSetDigest(addresses, bindingNonce),
        'x-folklore-egress-binding-nonce': bindingNonce,
      },
    });

    try {
      let response: Response;
      try {
        response = await this.fetchImpl(endpoint, {
          method: request.method,
          headers: new Headers({
            accept: 'application/json',
            authorization: `Bearer ${this.normalizeAccessToken(request.accessToken)}`,
            ...(body ? { 'content-type': 'application/json' } : {}),
          }),
          redirect: 'manual',
          signal: AbortSignal.timeout(this.timeoutMs),
          dispatcher: proxy,
          ...(body ? { body } : {}),
        } as RequestInit & { dispatcher: ProxyAgent });
      } catch {
        throw new ProviderEgressError();
      }
      if (response.status >= 400 && response.status < 500) {
        throw new ProviderRejectedError(response.status);
      }
      if (response.status !== request.expectedStatus) throw new ProviderEgressError();
      const bytes = await this.readResponse(response);
      if (!request.parseJson) return undefined;
      const contentType = response.headers
        .get('content-type')
        ?.split(';', 1)[0]
        ?.trim()
        .toLowerCase();
      if (contentType !== 'application/json') throw new ProviderEgressError();
      try {
        return JSON.parse(Buffer.from(bytes).toString('utf8')) as unknown;
      } catch {
        throw new JiraWebhookResponseError();
      }
    } catch (error) {
      if (
        error instanceof ProviderEgressError ||
        error instanceof ProviderRejectedError ||
        error instanceof JiraWebhookResponseError
      ) {
        throw error;
      }
      throw new ProviderEgressError();
    } finally {
      try {
        await proxy.close();
      } catch {
        // A close failure cannot expose provider response data.
      }
    }
  }

  private async providerAddresses(): Promise<readonly string[]> {
    let addresses: readonly string[];
    try {
      addresses = await this.resolve(JIRA_GATEWAY_HOST);
      assertPublicAddressSet(addresses);
      await this.assertProxyResolution(JIRA_GATEWAY_HOST, addresses);
    } catch {
      throw new ProviderEgressError();
    }
    return addresses;
  }

  private async readResponse(response: Response): Promise<Uint8Array> {
    const contentLength = response.headers.get('content-length');
    if (contentLength !== null) {
      const length = Number(contentLength);
      if (!Number.isSafeInteger(length) || length < 0 || length > this.maxResponseBytes) {
        throw new ProviderEgressError();
      }
    }
    if (!response.body) return new Uint8Array();
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > this.maxResponseBytes) {
        await reader.cancel();
        throw new ProviderEgressError();
      }
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  }

  private parseListPage(value: unknown): JiraWebhookPage {
    const record = this.asRecord(value);
    const rawValues = record['values'];
    if (!Array.isArray(rawValues) || rawValues.length > LIST_PAGE_SIZE) {
      throw new JiraWebhookResponseError();
    }
    const isLast = record['isLast'];
    if (isLast !== undefined && typeof isLast !== 'boolean') {
      throw new JiraWebhookResponseError();
    }
    const startAt = this.optionalInteger(record['startAt']) ?? 0;
    const total = this.optionalInteger(record['total']);
    return {
      values: rawValues.map((entry) => this.parseRegistration(entry)),
      isLast: isLast === true,
      startAt,
      total,
    };
  }

  private parseRegistration(value: unknown): JiraWebhookRegistration {
    const record = this.asRecord(value);
    const url = record['url'];
    const events = record['events'];
    const jqlFilter = record['jqlFilter'];
    const expirationDate = record['expirationDate'];
    if (
      typeof url !== 'string' ||
      Buffer.byteLength(url, 'utf8') > MAX_URL_BYTES ||
      !Array.isArray(events) ||
      events.length > MAX_EVENTS ||
      events.some(
        (event) => typeof event !== 'string' || Buffer.byteLength(event, 'utf8') > MAX_EVENT_BYTES,
      ) ||
      typeof jqlFilter !== 'string' ||
      Buffer.byteLength(jqlFilter, 'utf8') > MAX_JQL_BYTES
    ) {
      throw new JiraWebhookResponseError();
    }
    return {
      id: this.registrationId(record['id']),
      url,
      events: events.map((event) => String(event)),
      jqlFilter,
      expiresAt: this.dateString(expirationDate),
    };
  }

  private futureExpiration(value: unknown): string {
    const expiresAt = this.dateString(value);
    if (Date.parse(expiresAt) <= this.clock().getTime()) throw new JiraWebhookResponseError();
    return expiresAt;
  }

  private futureLifetime(): string {
    const now = this.clock();
    if (!Number.isFinite(now.getTime())) throw new JiraWebhookResponseError();
    return new Date(now.getTime() + WEBHOOK_LIFETIME_MS).toISOString();
  }

  private dateString(value: unknown): string {
    if (typeof value !== 'string') throw new JiraWebhookResponseError();
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp)) throw new JiraWebhookResponseError();
    try {
      return new Date(timestamp).toISOString();
    } catch {
      throw new JiraWebhookResponseError();
    }
  }

  private registrationIds(values: readonly string[]): string[] {
    if (values.length === 0 || values.length > MAX_REGISTRATION_IDS) {
      throw new ProviderEgressError();
    }
    const ids = values.map((value) => this.registrationId(value));
    if (new Set(ids).size !== ids.length) throw new ProviderEgressError();
    return ids;
  }

  private registrationId(value: unknown): string {
    if (
      (typeof value !== 'string' && typeof value !== 'number') ||
      (typeof value === 'string' &&
        (value.length > MAX_ID_DIGITS || !DECIMAL_ID_PATTERN.test(value))) ||
      (typeof value === 'number' && !Number.isSafeInteger(value))
    ) {
      throw new JiraWebhookResponseError();
    }
    const id = String(value);
    if (BigInt(id) > BigInt(Number.MAX_SAFE_INTEGER)) throw new JiraWebhookResponseError();
    return id;
  }

  private normalizeCloudId(value: string): string {
    if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw new ProviderEgressError();
    return value.toLowerCase();
  }

  private normalizeAccessToken(value: string): string {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      Buffer.byteLength(value, 'utf8') > MAX_TOKEN_BYTES
    ) {
      throw new ProviderEgressError();
    }
    return value;
  }

  private validateWebhookUrl(value: string): void {
    if (
      typeof value !== 'string' ||
      Buffer.byteLength(value, 'utf8') > MAX_URL_BYTES ||
      !JIRA_WEBHOOK_URL_PATTERN.test(value)
    ) {
      throw new ProviderEgressError();
    }
    try {
      const url = new URL(value);
      if (url.href !== value || url.username || url.password || url.hash) {
        throw new ProviderEgressError();
      }
    } catch (error) {
      if (error instanceof ProviderEgressError) throw error;
      throw new ProviderEgressError();
    }
  }

  private endpoint(cloudId: string, suffix: string): string {
    if (!/^\/?(?:\/refresh)?(?:\?startAt=[0-9]+&maxResults=[0-9]+)?$/.test(suffix)) {
      throw new ProviderEgressError();
    }
    const endpoint = `${JIRA_GATEWAY_ORIGIN}/ex/jira/${cloudId}${JIRA_WEBHOOK_PATH}${suffix}`;
    const parsed = new URL(endpoint);
    if (
      parsed.protocol !== 'https:' ||
      parsed.hostname !== JIRA_GATEWAY_HOST ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      parsed.port !== '' ||
      parsed.hash !== ''
    ) {
      throw new ProviderEgressError();
    }
    return endpoint;
  }

  private asRecord(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new JiraWebhookResponseError();
    }
    return value as Record<string, unknown>;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  private optionalInteger(value: unknown): number | null {
    if (value === undefined) return null;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
      throw new JiraWebhookResponseError();
    }
    return value;
  }

  private addressSetDigest(addresses: readonly string[], nonce: string): string {
    return createHash('sha256')
      .update(JSON.stringify({ addresses: [...addresses], nonce }))
      .digest('hex');
  }
}

class JiraWebhookResponseError extends Error {
  constructor() {
    super('jira_webhook_response_invalid');
    this.name = 'JiraWebhookResponseError';
  }
}
