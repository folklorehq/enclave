import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { TenantContext } from '../tenant/tenant-context.js';
import type {
  JiraWebhookReplayEntry,
  JiraWebhookReplayReservation,
} from './JiraWebhookAuthenticator.js';

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
const MAX_PERSIST_ATTEMPTS = 3;
const CLOCK_SKEW_MS = 60_000;
const REPLAY_ADMISSION_WINDOW_MS = 60 * 1000;
const REPLAY_LEASE_MS = 2 * 60 * 1000;
const CLEANUP_RECEIPT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CLEANUP_RECEIPTS = 4096;
const REPLAY_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const REPLAY_LEASE_ID_PATTERN = /^[a-f0-9]{64}$/;

interface ReplayState {
  records: Map<string, ReplayRecord>;
  admissionReservations: Map<string, number>;
  cleanupReceipts: Map<string, number>;
  loaded: boolean;
  etag?: string;
}

interface ReplayRecord {
  key: string;
  expiresAt: number;
  leaseExpiresAt: number;
  committed: boolean;
  leaseId: string | null;
}

/** Keeps Jira replay commitments encrypted in the tenant's processed-output bucket. */
export class S3JiraWebhookReplayStore {
  private readonly states = new Map<string, ReplayState>();
  private readonly tails = new Map<string, Promise<void>>();

  constructor(
    private readonly s3: S3Client,
    private readonly resolveTenant: (orgId: string) => TenantContext,
  ) {}

  async reserve(input: {
    orgId: string;
    replayEntries: readonly JiraWebhookReplayEntry[];
    leaseId: string;
  }): Promise<JiraWebhookReplayReservation> {
    return this.withOrgLock(input.orgId, () => this.reserveLocked(input));
  }

  async commit(input: {
    orgId: string;
    replayKeys: readonly string[];
    leaseId: string;
  }): Promise<void> {
    await this.withOrgLock(input.orgId, () => this.commitLocked(input));
  }

  async release(input: {
    orgId: string;
    replayKeys: readonly string[];
    leaseId: string;
  }): Promise<void> {
    await this.withOrgLock(input.orgId, () => this.releaseLocked(input));
  }

  async hasCleanupReceipt(input: { orgId: string; cleanupKey: string }): Promise<boolean> {
    if (!REPLAY_KEY_PATTERN.test(input.cleanupKey)) {
      throw new Error('jira_webhook_cleanup_receipt_input_invalid');
    }
    return this.withOrgLock(input.orgId, async () => {
      const state = await this.state(input.orgId);
      this.expire(state, Date.now());
      return state.cleanupReceipts.has(input.cleanupKey);
    });
  }

  async recordCleanupReceipt(input: { orgId: string; cleanupKey: string }): Promise<void> {
    if (!REPLAY_KEY_PATTERN.test(input.cleanupKey)) {
      throw new Error('jira_webhook_cleanup_receipt_input_invalid');
    }
    await this.withOrgLock(input.orgId, () => this.recordCleanupReceiptLocked(input));
  }

  private async withOrgLock<T>(orgId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(orgId) ?? Promise.resolve();
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => gate);
    this.tails.set(orgId, tail);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.tails.get(orgId) === tail) this.tails.delete(orgId);
    }
  }

  private async reserveLocked(input: {
    orgId: string;
    replayEntries: readonly JiraWebhookReplayEntry[];
    leaseId: string;
  }): Promise<JiraWebhookReplayReservation> {
    const replayEntries = this.validEntries(input.replayEntries);
    if (!replayEntries || !REPLAY_LEASE_ID_PATTERN.test(input.leaseId)) {
      throw new Error('jira_webhook_replay_input_invalid');
    }
    const replayKeys = replayEntries.map((entry) => entry.key);
    for (let attempt = 0; attempt < MAX_PERSIST_ATTEMPTS; attempt++) {
      const state = await this.state(input.orgId);
      const now = Date.now();
      this.expire(state, now);
      const reservation = this.existingReservation(state, replayKeys);
      if (reservation) return reservation;
      if (state.admissionReservations.size >= REPLAY_ADMISSION_LIMIT_PER_MINUTE) {
        throw new Error('jira_webhook_admission_rate_exhausted');
      }
      if (state.records.size + replayKeys.length > MAX_REPLAY_ENTRIES) {
        throw new Error('jira_webhook_replay_capacity_exhausted');
      }
      const leaseExpiresAt = now + REPLAY_LEASE_MS;
      for (const entry of replayEntries) {
        state.records.set(entry.key, {
          key: entry.key,
          expiresAt: entry.expiresAt,
          leaseExpiresAt,
          committed: false,
          leaseId: input.leaseId,
        });
      }
      state.admissionReservations.set(input.leaseId, now);
      try {
        await this.persist(input.orgId, state);
        return { status: 'reserved', leaseId: input.leaseId };
      } catch (error) {
        if (!this.isConditionalConflict(error) || attempt === MAX_PERSIST_ATTEMPTS - 1) {
          this.states.delete(input.orgId);
          throw new Error('jira_webhook_replay_persistence_failed');
        }
        this.states.delete(input.orgId);
      }
    }
    throw new Error('jira_webhook_replay_persistence_failed');
  }

  private async commitLocked(input: {
    orgId: string;
    replayKeys: readonly string[];
    leaseId: string;
  }): Promise<void> {
    const replayKeys = this.validKeys(input.replayKeys);
    if (!replayKeys || !REPLAY_LEASE_ID_PATTERN.test(input.leaseId)) {
      throw new Error('jira_webhook_replay_commit_failed');
    }
    for (let attempt = 0; attempt < MAX_PERSIST_ATTEMPTS; attempt++) {
      const state = await this.state(input.orgId);
      this.expire(state, Date.now());
      const records = replayKeys.map((key) => state.records.get(key));
      if (records.some((record) => record === undefined)) {
        throw new Error('jira_webhook_replay_commit_failed');
      }
      if (records.every((record) => record?.committed)) return;
      if (
        records.some(
          (record) =>
            !record ||
            (!record.committed &&
              (record.leaseId !== input.leaseId || record.leaseExpiresAt < Date.now())),
        )
      ) {
        throw new Error('jira_webhook_replay_commit_failed');
      }
      for (const key of replayKeys) {
        const record = state.records.get(key);
        if (record && record.leaseId === input.leaseId) record.committed = true;
      }
      try {
        await this.persist(input.orgId, state);
        return;
      } catch (error) {
        this.states.delete(input.orgId);
        if (!this.isConditionalConflict(error) || attempt === MAX_PERSIST_ATTEMPTS - 1) {
          throw new Error('jira_webhook_replay_commit_failed');
        }
      }
    }
    throw new Error('jira_webhook_replay_commit_failed');
  }

  private async releaseLocked(input: {
    orgId: string;
    replayKeys: readonly string[];
    leaseId: string;
  }): Promise<void> {
    const replayKeys = [...new Set(input.replayKeys)];
    if (
      replayKeys.length === 0 ||
      replayKeys.length > 2 ||
      replayKeys.some((key) => !REPLAY_KEY_PATTERN.test(key)) ||
      !REPLAY_LEASE_ID_PATTERN.test(input.leaseId)
    ) {
      return;
    }
    for (let attempt = 0; attempt < MAX_PERSIST_ATTEMPTS; attempt++) {
      const state = await this.state(input.orgId);
      this.expire(state, Date.now());
      let changed = false;
      for (const key of replayKeys) {
        const record = state.records.get(key);
        if (record && !record.committed && record.leaseId === input.leaseId) {
          changed = state.records.delete(key) || changed;
        }
      }
      if (!changed) return;
      try {
        await this.persist(input.orgId, state);
        return;
      } catch (error) {
        if (!this.isConditionalConflict(error) || attempt === MAX_PERSIST_ATTEMPTS - 1) {
          this.states.delete(input.orgId);
          throw new Error('jira_webhook_replay_release_failed');
        }
        this.states.delete(input.orgId);
      }
    }
    throw new Error('jira_webhook_replay_release_failed');
  }

  private async recordCleanupReceiptLocked(input: {
    orgId: string;
    cleanupKey: string;
  }): Promise<void> {
    for (let attempt = 0; attempt < MAX_PERSIST_ATTEMPTS; attempt++) {
      const state = await this.state(input.orgId);
      this.expire(state, Date.now());
      if (state.cleanupReceipts.has(input.cleanupKey)) return;
      if (state.cleanupReceipts.size >= MAX_CLEANUP_RECEIPTS) {
        throw new Error('jira_webhook_cleanup_receipt_capacity_exhausted');
      }
      state.cleanupReceipts.set(input.cleanupKey, Date.now());
      try {
        await this.persist(input.orgId, state);
        return;
      } catch (error) {
        this.states.delete(input.orgId);
        if (!this.isConditionalConflict(error) || attempt === MAX_PERSIST_ATTEMPTS - 1) {
          throw new Error('jira_webhook_cleanup_receipt_persistence_failed');
        }
      }
    }
    throw new Error('jira_webhook_cleanup_receipt_persistence_failed');
  }

  private async state(orgId: string): Promise<ReplayState> {
    const existing = this.states.get(orgId);
    if (existing?.loaded) return existing;
    const state = existing ?? {
      records: new Map<string, ReplayRecord>(),
      admissionReservations: new Map<string, number>(),
      cleanupReceipts: new Map<string, number>(),
      loaded: false,
    };
    const tenant = this.resolveTenant(orgId);
    try {
      const object = await this.s3.send(
        new GetObjectCommand({
          Bucket: tenant.processedOutputsBucket,
          Key: this.objectKey(orgId),
        }),
      );
      if (!object.Body) throw new Error('jira_webhook_replay_state_empty');
      state.etag = object.ETag;
      if (!state.etag) throw new Error('jira_webhook_replay_state_version_unavailable');
      const raw = await object.Body.transformToByteArray();
      const ciphertext = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      raw.fill(0);
      let plaintext: Buffer;
      try {
        plaintext = await tenant.crypto.decryptJiraWebhookReplay(ciphertext, { orgId });
      } finally {
        ciphertext.fill(0);
      }
      try {
        this.loadState(state, JSON.parse(plaintext.toString('utf8')) as unknown);
      } finally {
        plaintext.fill(0);
      }
    } catch (error) {
      if (!this.isMissingObject(error)) throw error;
    }
    state.loaded = true;
    this.states.set(orgId, state);
    return state;
  }

  private async persist(orgId: string, state: ReplayState): Promise<void> {
    const tenant = this.resolveTenant(orgId);
    const plaintext = Buffer.from(
      JSON.stringify({
        records: [...state.records.values()],
        admissionReservations: [...state.admissionReservations.entries()].map(
          ([leaseId, reservedAt]) => ({ leaseId, reservedAt }),
        ),
        cleanupReceipts: [...state.cleanupReceipts.entries()].map(([key, completedAt]) => ({
          key,
          completedAt,
        })),
      }),
      'utf8',
    );
    let ciphertext: Buffer;
    try {
      ciphertext = await tenant.crypto.encryptJiraWebhookReplay(plaintext, { orgId });
    } finally {
      plaintext.fill(0);
    }
    try {
      const result = await this.s3.send(
        new PutObjectCommand({
          Bucket: tenant.processedOutputsBucket,
          Key: this.objectKey(orgId),
          Body: ciphertext.toString('base64'),
          ContentType: 'text/plain',
          ...(state.etag ? { IfMatch: state.etag } : { IfNoneMatch: '*' }),
        }),
      );
      if (!result.ETag) throw new Error('jira_webhook_replay_state_version_unavailable');
      state.etag = result.ETag;
    } finally {
      ciphertext.fill(0);
    }
  }

  private loadRecords(records: Map<string, ReplayRecord>, value: unknown): void {
    if (!Array.isArray(value)) throw new Error('jira_webhook_replay_state_invalid');
    for (const entry of value) {
      if (!entry || typeof entry !== 'object') throw new Error('jira_webhook_replay_state_invalid');
      const candidate = entry as Record<string, unknown>;
      const key = candidate['key'];
      const expiresAt = candidate['expiresAt'];
      const leaseExpiresAt = candidate['leaseExpiresAt'];
      const committed = candidate['committed'];
      const leaseId = candidate['leaseId'];
      if (
        typeof key !== 'string' ||
        !REPLAY_KEY_PATTERN.test(key) ||
        typeof expiresAt !== 'number' ||
        !Number.isSafeInteger(expiresAt) ||
        (leaseExpiresAt !== undefined &&
          (typeof leaseExpiresAt !== 'number' || !Number.isSafeInteger(leaseExpiresAt))) ||
        (committed !== undefined && typeof committed !== 'boolean') ||
        (leaseId !== undefined &&
          (typeof leaseId !== 'string' || !REPLAY_LEASE_ID_PATTERN.test(leaseId))) ||
        (committed === false && leaseId === undefined)
      ) {
        throw new Error('jira_webhook_replay_state_invalid');
      }
      if (records.size >= MAX_REPLAY_ENTRIES) throw new Error('jira_webhook_replay_state_large');
      records.set(key, {
        key,
        expiresAt,
        leaseExpiresAt: typeof leaseExpiresAt === 'number' ? leaseExpiresAt : expiresAt,
        committed: committed === undefined ? true : committed,
        leaseId: typeof leaseId === 'string' ? leaseId : null,
      });
    }
  }

  private loadState(state: ReplayState, value: unknown): void {
    if (Array.isArray(value)) {
      this.loadRecords(state.records, value);
      return;
    }
    if (!value || typeof value !== 'object') throw new Error('jira_webhook_replay_state_invalid');
    const candidate = value as Record<string, unknown>;
    const records = candidate['records'];
    const admissionReservations = candidate['admissionReservations'];
    const cleanupReceipts = candidate['cleanupReceipts'];
    if (
      !Array.isArray(records) ||
      (admissionReservations !== undefined && !Array.isArray(admissionReservations)) ||
      !Array.isArray(cleanupReceipts)
    ) {
      throw new Error('jira_webhook_replay_state_invalid');
    }
    this.loadRecords(state.records, records);
    if (Array.isArray(admissionReservations)) {
      this.loadAdmissionReservations(state.admissionReservations, admissionReservations);
    }
    for (const entry of cleanupReceipts) {
      if (!entry || typeof entry !== 'object') {
        throw new Error('jira_webhook_replay_state_invalid');
      }
      const receipt = entry as Record<string, unknown>;
      const key = receipt['key'];
      const completedAt = receipt['completedAt'];
      if (
        typeof key !== 'string' ||
        !REPLAY_KEY_PATTERN.test(key) ||
        typeof completedAt !== 'number' ||
        !Number.isSafeInteger(completedAt)
      ) {
        throw new Error('jira_webhook_replay_state_invalid');
      }
      if (state.cleanupReceipts.size >= MAX_CLEANUP_RECEIPTS) {
        throw new Error('jira_webhook_replay_state_large');
      }
      state.cleanupReceipts.set(key, completedAt);
    }
  }

  private expire(state: ReplayState, now: number): void {
    for (const [key, record] of state.records) {
      if (
        record.expiresAt < now - CLOCK_SKEW_MS ||
        (!record.committed && record.leaseExpiresAt < now)
      ) {
        state.records.delete(key);
      }
    }
    for (const [leaseId, reservedAt] of state.admissionReservations) {
      if (reservedAt < now - REPLAY_ADMISSION_WINDOW_MS) {
        state.admissionReservations.delete(leaseId);
      }
    }
    for (const [key, completedAt] of state.cleanupReceipts) {
      if (completedAt < now - CLEANUP_RECEIPT_RETENTION_MS) state.cleanupReceipts.delete(key);
    }
  }

  private loadAdmissionReservations(reservations: Map<string, number>, value: unknown[]): void {
    for (const entry of value) {
      if (!entry || typeof entry !== 'object') {
        throw new Error('jira_webhook_replay_state_invalid');
      }
      const candidate = entry as Record<string, unknown>;
      const leaseId = candidate['leaseId'];
      const reservedAt = candidate['reservedAt'];
      if (
        typeof leaseId !== 'string' ||
        !REPLAY_LEASE_ID_PATTERN.test(leaseId) ||
        typeof reservedAt !== 'number' ||
        !Number.isSafeInteger(reservedAt)
      ) {
        throw new Error('jira_webhook_replay_state_invalid');
      }
      if (reservations.size >= REPLAY_ADMISSION_LIMIT_PER_MINUTE) {
        throw new Error('jira_webhook_replay_state_large');
      }
      reservations.set(leaseId, reservedAt);
    }
  }

  private existingReservation(
    state: ReplayState,
    replayKeys: readonly string[],
  ): JiraWebhookReplayReservation | null {
    let inFlight = false;
    for (const key of replayKeys) {
      const record = state.records.get(key);
      if (!record) continue;
      if (record.committed) return { status: 'committed' };
      if (record.leaseExpiresAt >= Date.now()) inFlight = true;
    }
    return inFlight ? { status: 'in_flight' } : null;
  }

  private validKeys(keys: readonly string[]): string[] | null {
    const replayKeys = [...new Set(keys)];
    return replayKeys.length > 0 &&
      replayKeys.length <= 2 &&
      replayKeys.every((key) => REPLAY_KEY_PATTERN.test(key))
      ? replayKeys
      : null;
  }

  private validEntries(
    entries: readonly JiraWebhookReplayEntry[],
  ): JiraWebhookReplayEntry[] | null {
    const replayEntries = [...entries];
    const keys = replayEntries.map((entry) => entry.key);
    return replayEntries.length > 0 &&
      replayEntries.length <= 2 &&
      new Set(keys).size === keys.length &&
      replayEntries.every(
        (entry) => REPLAY_KEY_PATTERN.test(entry.key) && Number.isSafeInteger(entry.expiresAt),
      )
      ? replayEntries
      : null;
  }

  private objectKey(orgId: string): string {
    return `jira-webhook-replay/${orgId}.json`;
  }

  private isMissingObject(error: unknown): boolean {
    if (error instanceof NoSuchKey) return true;
    if (!error || typeof error !== 'object') return false;
    const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
    return (
      (candidate.name === 'NoSuchKey' || candidate.name === 'NotFound') &&
      candidate.$metadata?.httpStatusCode === 404
    );
  }

  private isConditionalConflict(error: unknown): boolean {
    if (!error || typeof error !== 'object') return false;
    const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
    return (
      candidate.name === 'PreconditionFailed' ||
      candidate.name === 'ConditionalRequestConflict' ||
      candidate.$metadata?.httpStatusCode === 409 ||
      candidate.$metadata?.httpStatusCode === 412
    );
  }
}
