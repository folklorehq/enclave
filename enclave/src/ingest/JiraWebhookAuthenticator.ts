import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const JWT_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const HEX_64_PATTERN = /^[a-f0-9]{64}$/;
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_CLAIMS_BYTES = 128 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_PATH_BYTES = 512;
const MAX_QUERY_BYTES = 8 * 1024;
const MAX_WEBHOOK_IDENTIFIER_BYTES = 256;
const REPLAY_ADMISSION_LIMIT_PER_MINUTE = 120;
const REPLAY_RETENTION_MINUTES = 24 * 60;
const REPLAY_KEYS_PER_DELIVERY = 2;
const REPLAY_CAPACITY_HEADROOM = 1.5;
const MAX_REPLAY_ENTRIES = Math.ceil(
  REPLAY_ADMISSION_LIMIT_PER_MINUTE *
    REPLAY_RETENTION_MINUTES *
    REPLAY_KEYS_PER_DELIVERY *
    REPLAY_CAPACITY_HEADROOM,
);
const REPLAY_ADMISSION_WINDOW_MS = 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;
const DEFAULT_MAX_LIFETIME_SECONDS = 600;

export type JiraWebhookMode = 'off' | 'capture' | 'enabled';
export type JiraWebhookReplayReservation =
  | { status: 'reserved'; leaseId: string }
  | { status: 'committed' }
  | { status: 'in_flight' };

export interface JiraWebhookReplayEntry {
  key: string;
  expiresAt: number;
}

export interface JiraWebhookClaimPolicy {
  mode?: JiraWebhookMode;
  issuer?: string;
  audience?: string;
  tenantClaimName?: string;
  qshClaimName?: string;
  matchedWebhookIdsClaimName?: string;
  maxLifetimeSeconds?: number;
}

export interface JiraWebhookAuthenticationInput {
  orgId: string;
  sourceKind: string;
  externalTenantId: string;
  webhookRouteId: string;
  webhookRegistrationIds: readonly string[] | null;
  authorization: string;
  method: string;
  rawPath: string;
  rawQuery: string;
  webhookIdentifier: string;
}

export interface JiraWebhookAuthenticationResult {
  registrationId: string;
  webhookIdentifier: string;
  commitReplay: () => Promise<void>;
  releaseReplay: () => Promise<void>;
}

export interface JiraWebhookAuthenticatorOptions extends JiraWebhookClaimPolicy {
  clock?: () => Date;
  loadClientSecret: () => Promise<string>;
  reserveReplay?: (input: {
    orgId: string;
    replayEntries: readonly JiraWebhookReplayEntry[];
    leaseId: string;
  }) => Promise<JiraWebhookReplayReservation>;
  commitReplay?: (input: {
    orgId: string;
    replayKeys: readonly string[];
    leaseId: string;
  }) => Promise<void>;
  releaseReplay?: (input: {
    orgId: string;
    replayKeys: readonly string[];
    leaseId: string;
  }) => Promise<void>;
}

interface JwtParts {
  encodedHeader: string;
  encodedPayload: string;
  encodedSignature: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

interface ReplayEntry {
  key: string;
  expiresAt: number;
  leaseExpiresAt: number;
  committed: boolean;
  leaseId: string;
}

const REPLAY_LEASE_MS = 2 * 60 * 1000;
const DELIVERY_REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000;

/** Verifies the signed Jira webhook envelope entirely inside the enclave. */
export class JiraWebhookAuthenticator {
  private readonly clock: () => Date;
  private readonly loadClientSecret: () => Promise<string>;
  private readonly mode: JiraWebhookMode;
  private readonly issuer: string | undefined;
  private readonly audience: string | undefined;
  private readonly tenantClaimName: string | undefined;
  private readonly qshClaimName: string;
  private readonly matchedWebhookIdsClaimName: string;
  private readonly maxLifetimeSeconds: number;
  private readonly reserveReplay:
    | ((input: {
        orgId: string;
        replayEntries: readonly JiraWebhookReplayEntry[];
        leaseId: string;
      }) => Promise<JiraWebhookReplayReservation>)
    | undefined;
  private readonly commitReplay:
    | ((input: { orgId: string; replayKeys: readonly string[]; leaseId: string }) => Promise<void>)
    | undefined;
  private readonly releaseReplay:
    | ((input: { orgId: string; replayKeys: readonly string[]; leaseId: string }) => Promise<void>)
    | undefined;
  private readonly replay = new Map<string, Map<string, ReplayEntry>>();
  private readonly admissionReservations = new Map<string, Map<string, number>>();

  constructor(options: JiraWebhookAuthenticatorOptions) {
    this.clock = options.clock ?? (() => new Date());
    this.loadClientSecret = options.loadClientSecret;
    this.mode = options.mode ?? 'off';
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.tenantClaimName = options.tenantClaimName;
    this.qshClaimName = options.qshClaimName ?? 'qsh';
    this.matchedWebhookIdsClaimName = options.matchedWebhookIdsClaimName ?? 'matchedWebhookIds';
    this.maxLifetimeSeconds = options.maxLifetimeSeconds ?? DEFAULT_MAX_LIFETIME_SECONDS;
    this.reserveReplay = options.reserveReplay;
    this.commitReplay = options.commitReplay;
    this.releaseReplay = options.releaseReplay;
    if (this.mode === 'enabled' && (!this.issuer || !this.audience || !this.tenantClaimName)) {
      throw new Error('jira_webhook_claim_policy_incomplete');
    }
    if (
      !Number.isSafeInteger(this.maxLifetimeSeconds) ||
      this.maxLifetimeSeconds < 1 ||
      this.maxLifetimeSeconds > 86_400
    ) {
      throw new Error('jira_webhook_lifetime_policy_invalid');
    }
  }

  async authenticate(
    input: JiraWebhookAuthenticationInput,
  ): Promise<JiraWebhookAuthenticationResult | null> {
    if (this.mode !== 'enabled' || !this.isBoundInput(input)) return null;
    const token = this.bearerToken(input.authorization);
    if (!token) return null;
    const parts = this.parseToken(token);
    if (!parts || !this.isValidHeader(parts.header)) return null;
    const now = this.clock();
    const lifetime = this.validLifetime(parts.payload, now);
    if (lifetime === null) return null;
    const expiresAt = lifetime.expiresAt * 1000;
    if (!this.matchesConfiguredClaims(parts.payload, input)) return null;
    const qsh = stringClaim(parts.payload[this.qshClaimName]);
    if (!qsh || !HEX_64_PATTERN.test(qsh)) return null;
    if (
      !this.constantTimeHexEqual(qsh, queryStringHash(input.method, input.rawPath, input.rawQuery))
    ) {
      return null;
    }
    const secret = await this.secret();
    if (!secret) return null;
    if (!this.verifySignature(parts, secret)) return null;
    const registrationId = this.matchedRegistrationId(parts.payload, input.webhookRegistrationIds);
    if (!registrationId) return null;
    const replayEntries = [
      {
        key: `${input.orgId}:jira:${input.webhookRouteId}:delivery:${this.digest(input.webhookIdentifier)}`,
        expiresAt: now.getTime() + DELIVERY_REPLAY_RETENTION_MS,
      },
      {
        key: `${input.orgId}:jira:${input.webhookRouteId}:token:${this.tokenDigest(token)}`,
        expiresAt,
      },
    ];
    const replayKeys = replayEntries.map((entry) => entry.key);
    const localReservation = this.replayReservation(input.orgId, replayKeys);
    if (localReservation?.status === 'committed') return null;
    if (localReservation?.status === 'in_flight') throw new Error('jira_webhook_replay_in_flight');
    const leaseId = this.newLeaseId();
    if (this.reserveReplay) {
      const reservation = await this.reserveReplay({
        orgId: input.orgId,
        replayEntries,
        leaseId,
      });
      if (reservation.status === 'committed') return null;
      if (reservation.status === 'in_flight') throw new Error('jira_webhook_replay_in_flight');
      if (reservation.leaseId !== leaseId) throw new Error('jira_webhook_replay_lease_mismatch');
    }
    try {
      this.remember(input.orgId, replayEntries, leaseId);
    } catch (error) {
      if (this.releaseReplay) {
        await this.releaseReplay({ orgId: input.orgId, replayKeys, leaseId });
      }
      throw error;
    }
    let committed = false;
    let released = false;
    return {
      registrationId,
      webhookIdentifier: input.webhookIdentifier,
      commitReplay: async () => {
        if (committed) return;
        if (released) throw new Error('jira_webhook_replay_released');
        if (this.commitReplay) {
          await this.commitReplay({ orgId: input.orgId, replayKeys, leaseId });
          this.forgetReplay(input.orgId, replayKeys, leaseId);
        } else {
          this.commitLocal(input.orgId, replayKeys, leaseId);
        }
        committed = true;
      },
      releaseReplay: async () => {
        if (released || committed) return;
        released = true;
        this.forget(input.orgId, replayKeys, leaseId);
        if (this.releaseReplay)
          await this.releaseReplay({ orgId: input.orgId, replayKeys, leaseId });
      },
    };
  }

  private isBoundInput(input: JiraWebhookAuthenticationInput): boolean {
    return (
      input.sourceKind === 'jira' &&
      UUID_PATTERN.test(input.orgId) &&
      UUID_PATTERN.test(input.externalTenantId) &&
      UUID_PATTERN.test(input.webhookRouteId) &&
      input.webhookRegistrationIds !== null &&
      input.webhookRegistrationIds.length > 0 &&
      input.webhookRegistrationIds.length <= 16 &&
      input.webhookRegistrationIds.every((id) => /^(?:0|[1-9][0-9]{0,15})$/.test(id)) &&
      input.method === 'POST' &&
      input.rawPath === `/ingest/${input.orgId}/jira` &&
      Buffer.byteLength(input.rawPath, 'utf8') <= MAX_PATH_BYTES &&
      Buffer.byteLength(input.rawQuery, 'utf8') <= MAX_QUERY_BYTES &&
      Buffer.byteLength(input.webhookIdentifier, 'utf8') > 0 &&
      Buffer.byteLength(input.webhookIdentifier, 'utf8') <= MAX_WEBHOOK_IDENTIFIER_BYTES &&
      this.routeInQuery(input.rawQuery, input.webhookRouteId)
    );
  }

  private bearerToken(value: string): string | null {
    if (!/^Bearer [^\s]+$/.test(value)) return null;
    const token = value.slice('Bearer '.length);
    return Buffer.byteLength(token, 'utf8') <= MAX_TOKEN_BYTES ? token : null;
  }

  private parseToken(token: string): JwtParts | null {
    const segments = token.split('.');
    if (segments.length !== 3 || segments.some((segment) => !JWT_SEGMENT_PATTERN.test(segment))) {
      return null;
    }
    const [encodedHeader, encodedPayload, encodedSignature] = segments;
    if (!encodedHeader || !encodedPayload || !encodedSignature) return null;
    const header = this.parseJsonObject(encodedHeader, MAX_HEADER_BYTES);
    const payload = this.parseJsonObject(encodedPayload, MAX_CLAIMS_BYTES);
    if (!header || !payload) return null;
    return { encodedHeader, encodedPayload, encodedSignature, header, payload };
  }

  private parseJsonObject(segment: string, maxBytes: number): Record<string, unknown> | null {
    let bytes: Buffer;
    try {
      bytes = Buffer.from(segment, 'base64url');
    } catch {
      return null;
    }
    if (bytes.byteLength > maxBytes) return null;
    try {
      const value: unknown = JSON.parse(bytes.toString('utf8'));
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  }

  private isValidHeader(header: Record<string, unknown>): boolean {
    return header['alg'] === 'HS256' && (header['typ'] === undefined || header['typ'] === 'JWT');
  }

  private validLifetime(payload: Record<string, unknown>, now: Date): { expiresAt: number } | null {
    const iat = numericClaim(payload['iat']);
    const exp = numericClaim(payload['exp']);
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (iat === null || exp === null || !Number.isFinite(nowSeconds)) return null;
    if (
      exp <= iat ||
      exp - iat > this.maxLifetimeSeconds ||
      iat > nowSeconds + CLOCK_SKEW_SECONDS ||
      exp < nowSeconds - CLOCK_SKEW_SECONDS
    ) {
      return null;
    }
    return { expiresAt: exp };
  }

  private matchesConfiguredClaims(
    payload: Record<string, unknown>,
    input: JiraWebhookAuthenticationInput,
  ): boolean {
    if (this.issuer !== undefined && payload['iss'] !== this.issuer) return false;
    if (this.audience !== undefined && !this.matchesAudience(payload['aud'], this.audience)) {
      return false;
    }
    if (
      this.tenantClaimName !== undefined &&
      payload[this.tenantClaimName] !== input.externalTenantId
    ) {
      return false;
    }
    return true;
  }

  private matchesAudience(value: unknown, expected: string): boolean {
    return (
      value === expected || (Array.isArray(value) && value.length === 1 && value[0] === expected)
    );
  }

  private verifySignature(parts: JwtParts, secret: string): boolean {
    const expected = createHmac('sha256', secret)
      .update(`${parts.encodedHeader}.${parts.encodedPayload}`, 'ascii')
      .digest();
    let supplied: Buffer;
    try {
      supplied = Buffer.from(parts.encodedSignature, 'base64url');
    } catch {
      return false;
    }
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  }

  private matchedRegistrationId(
    payload: Record<string, unknown>,
    currentIds: readonly string[] | null,
  ): string | null {
    if (!currentIds) return null;
    const values = payload[this.matchedWebhookIdsClaimName];
    if (!Array.isArray(values) || values.length === 0 || values.length > 16) return null;
    const candidates = values.map((value) => this.registrationId(value)).filter(Boolean);
    return candidates.find((id): id is string => id !== null && currentIds.includes(id)) ?? null;
  }

  private registrationId(value: unknown): string | null {
    if (typeof value === 'string' && /^(?:0|[1-9][0-9]{0,15})$/.test(value)) return value;
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
      return String(value);
    }
    return null;
  }

  private routeInQuery(rawQuery: string, expectedRoute: string): boolean {
    const values = this.queryValues(rawQuery, 'route');
    return values.length === 1 && values[0] === expectedRoute;
  }

  private queryValues(rawQuery: string, key: string): string[] {
    if (!rawQuery) return [];
    const values: string[] = [];
    for (const part of rawQuery.split('&')) {
      if (!part) continue;
      const separator = part.indexOf('=');
      const encodedKey = separator === -1 ? part : part.slice(0, separator);
      const encodedValue = separator === -1 ? '' : part.slice(separator + 1);
      try {
        if (decodeURIComponent(encodedKey.replace(/\+/g, ' ')) === key) {
          values.push(decodeURIComponent(encodedValue.replace(/\+/g, ' ')));
        }
      } catch {
        return [];
      }
    }
    return values;
  }

  private async secret(): Promise<string> {
    const value = await this.loadClientSecret();
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('jira_webhook_secret_unavailable');
    }
    return value;
  }

  private replayReservation(
    orgId: string,
    keys: readonly string[],
  ): JiraWebhookReplayReservation | null {
    this.expireReplay();
    const replay = this.replay.get(orgId);
    if (!replay) return null;
    let inFlight = false;
    for (const key of keys) {
      const previous = replay.get(key);
      if (previous === undefined) continue;
      if (previous.committed) return { status: 'committed' };
      inFlight = true;
    }
    return inFlight ? { status: 'in_flight' } : null;
  }

  private remember(
    orgId: string,
    entries: readonly JiraWebhookReplayEntry[],
    leaseId: string,
  ): void {
    this.expireReplay();
    const replay = this.replay.get(orgId) ?? new Map<string, ReplayEntry>();
    const admissions = this.admissionReservations.get(orgId) ?? new Map<string, number>();
    if (!this.reserveReplay && admissions.size >= REPLAY_ADMISSION_LIMIT_PER_MINUTE) {
      throw new Error('jira_webhook_admission_rate_exhausted');
    }
    const newKeys = entries.filter((entry) => !replay.has(entry.key));
    if (replay.size + newKeys.length > MAX_REPLAY_ENTRIES) {
      throw new Error('jira_webhook_replay_capacity_exhausted');
    }
    const leaseExpiresAt = this.clock().getTime() + REPLAY_LEASE_MS;
    for (const entry of entries) {
      replay.set(entry.key, {
        key: entry.key,
        expiresAt: entry.expiresAt,
        leaseExpiresAt: Math.min(entry.expiresAt, leaseExpiresAt),
        committed: false,
        leaseId,
      });
    }
    this.replay.set(orgId, replay);
    if (!this.reserveReplay) {
      admissions.set(leaseId, this.clock().getTime());
      this.admissionReservations.set(orgId, admissions);
    }
  }

  private forget(orgId: string, keys: readonly string[], leaseId: string): void {
    this.forgetReplay(orgId, keys, leaseId);
  }

  private forgetReplay(orgId: string, keys: readonly string[], leaseId: string): void {
    const replay = this.replay.get(orgId);
    if (!replay) return;
    for (const key of keys) {
      const entry = replay.get(key);
      if (entry && !entry.committed && entry.leaseId === leaseId) replay.delete(key);
    }
    if (replay.size === 0) this.replay.delete(orgId);
  }

  private commitLocal(orgId: string, keys: readonly string[], leaseId: string): void {
    const replay = this.replay.get(orgId);
    if (!replay) throw new Error('jira_webhook_replay_commit_failed');
    for (const key of keys) {
      const entry = replay.get(key);
      if (!entry || entry.leaseId !== leaseId) throw new Error('jira_webhook_replay_commit_failed');
      entry.committed = true;
    }
  }

  private expireReplay(): void {
    const now = this.clock().getTime();
    for (const [orgId, replay] of this.replay) {
      for (const [key, entry] of replay) {
        if (
          !Number.isFinite(now) ||
          entry.expiresAt < now ||
          (!entry.committed && entry.leaseExpiresAt < now)
        ) {
          replay.delete(key);
        }
      }
      if (replay.size === 0) this.replay.delete(orgId);
    }
    for (const [orgId, admissions] of this.admissionReservations) {
      for (const [leaseId, reservedAt] of admissions) {
        if (reservedAt < now - REPLAY_ADMISSION_WINDOW_MS) admissions.delete(leaseId);
      }
      if (admissions.size === 0) this.admissionReservations.delete(orgId);
    }
  }

  private constantTimeHexEqual(left: string, right: string): boolean {
    const leftBytes = Buffer.from(left, 'hex');
    const rightBytes = Buffer.from(right, 'hex');
    return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
  }

  private tokenDigest(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
  }

  private digest(value: string): string {
    return createHash('sha256').update(value, 'utf8').digest('hex');
  }

  private newLeaseId(): string {
    return randomBytes(32).toString('hex');
  }
}

export function queryStringHash(method: string, rawPath: string, rawQuery: string): string {
  const canonical = `${method.toUpperCase()}&${canonicalUri(rawPath)}&${canonicalQuery(rawQuery)}`;
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function canonicalUri(rawPath: string): string {
  const withoutTrailingSlash = rawPath.length > 1 ? rawPath.replace(/\/+$/, '') : rawPath;
  return withoutTrailingSlash.replace(/&/g, '%26');
}

function canonicalQuery(rawQuery: string): string {
  const grouped = new Map<string, string[]>();
  for (const part of rawQuery.split('&')) {
    if (!part) continue;
    const separator = part.indexOf('=');
    const rawKey = separator === -1 ? part : part.slice(0, separator);
    const rawValue = separator === -1 ? '' : part.slice(separator + 1);
    let key: string;
    let value: string;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
      value = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    } catch {
      return '';
    }
    const values = grouped.get(key) ?? [];
    values.push(value);
    grouped.set(key, values);
  }
  return [...grouped.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(
      ([key, values]) => `${encodeComponent(key)}=${values.sort().map(encodeComponent).join(',')}`,
    )
    .join('&');
}

function encodeComponent(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function numericClaim(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function stringClaim(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}
