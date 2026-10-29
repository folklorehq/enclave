import {
  GetObjectCommand,
  NoSuchKey,
  PutObjectCommand,
  type GetObjectCommandOutput,
  type S3Client,
} from '@aws-sdk/client-s3';
import { RESOURCE_SCOPE_MAX_SELECTED, resourceIdSchema } from '@folklore/contracts';
import { z } from 'zod';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  ResourceScopeConflictError,
  ResourceScopeInvalidError,
  ResourceScopeUnavailableError,
} from './resource-scope-errors.js';
import { isS3ConditionalConflict } from '../storage/s3-conditional.js';

const RESOURCE_SCOPE_FORMAT_VERSION = 1;
const RESOURCE_SCOPE_OBJECT_PURPOSE = 'resource-scope';

export const resourceScopeSchema = z
  .object({
    formatVersion: z.literal(RESOURCE_SCOPE_FORMAT_VERSION),
    revision: z.number().int().nonnegative(),
    mode: z.enum(['all', 'selected']),
    resourceIds: z.array(resourceIdSchema).max(RESOURCE_SCOPE_MAX_SELECTED),
    backfill: z.enum(['none', 'owed', 'running']),
    paused: z.boolean().default(false),
  })
  .strict()
  .refine((scope) => (scope.mode === 'all') === (scope.resourceIds.length === 0));

export type ResourceScope = z.infer<typeof resourceScopeSchema>;
export type ResourceScopeBackfill = ResourceScope['backfill'];

export interface ResourceScopeKey {
  orgId: string;
  deploymentId: string;
  sourceKind: string;
}

export type ResourceScopeWrite = ResourceScopeKey & {
  expectedRevision: number;
  mode: 'all' | 'selected';
  resourceIds: readonly string[];
};

export type ResourceScopeBackfillTransition = ResourceScopeKey & {
  expectedRevision: number;
  from: Exclude<ResourceScopeBackfill, 'none'>;
  to: Exclude<ResourceScopeBackfill, 'owed'>;
};

export type ResourceScopePause = ResourceScopeKey & {
  expectedRevision: number;
  paused: boolean;
};

export const DEFAULT_RESOURCE_SCOPE: ResourceScope = {
  formatVersion: RESOURCE_SCOPE_FORMAT_VERSION,
  revision: 0,
  mode: 'all',
  resourceIds: [],
  backfill: 'none',
  paused: false,
};

export interface ResourceScopeStoreDeps {
  s3: S3Client;
  bucket: string;
  crypto: EnclaveCrypto;
}

interface ScopeState {
  scope: ResourceScope;
  etag: string | undefined;
}

/** Stores the per-source resource scope only as tenant-bound ESDK ciphertext; ids, never names. */
export class ResourceScopeStore {
  constructor(private readonly deps: ResourceScopeStoreDeps) {}

  async read(key: ResourceScopeKey): Promise<ResourceScope> {
    return (await this.readState(key)).scope;
  }

  async write(input: ResourceScopeWrite): Promise<ResourceScope> {
    const resourceIds = this.normalizedIds(input);
    const state = await this.readState(input);
    this.requireRevision(state.scope, input.expectedRevision);
    const next: ResourceScope = {
      formatVersion: RESOURCE_SCOPE_FORMAT_VERSION,
      revision: state.scope.revision + 1,
      mode: input.mode,
      resourceIds,
      paused: state.scope.paused,
      backfill: this.widens(state.scope, input.mode, resourceIds) ? 'owed' : state.scope.backfill,
    };
    await this.persist(input, next, state.etag);
    return next;
  }

  async transitionBackfill(input: ResourceScopeBackfillTransition): Promise<ResourceScope> {
    const state = await this.readState(input);
    this.requireRevision(state.scope, input.expectedRevision);
    if (state.scope.backfill !== input.from) throw new ResourceScopeConflictError();
    const next: ResourceScope = { ...state.scope, backfill: input.to };
    await this.persist(input, next, state.etag);
    return next;
  }

  async setPaused(input: ResourceScopePause): Promise<{ scope: ResourceScope; changed: boolean }> {
    const state = await this.readState(input);
    this.requireRevision(state.scope, input.expectedRevision);
    if (state.scope.paused === input.paused) return { scope: state.scope, changed: false };
    const next: ResourceScope = {
      ...state.scope,
      revision: state.scope.revision + 1,
      paused: input.paused,
    };
    await this.persist(input, next, state.etag);
    return { scope: next, changed: true };
  }

  private requireRevision(scope: ResourceScope, expectedRevision: number): void {
    if (scope.revision !== expectedRevision) throw new ResourceScopeConflictError();
  }

  private normalizedIds(input: ResourceScopeWrite): string[] {
    const ids = [...new Set(input.resourceIds)].sort();
    const valid =
      input.mode === 'all'
        ? ids.length === 0
        : ids.length >= 1 &&
          ids.length <= RESOURCE_SCOPE_MAX_SELECTED &&
          ids.every((id) => resourceIdSchema.safeParse(id).success);
    if (!valid || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) {
      throw new ResourceScopeInvalidError();
    }
    return ids;
  }

  private widens(
    current: ResourceScope,
    mode: ResourceScope['mode'],
    resourceIds: readonly string[],
  ): boolean {
    if (current.mode === 'all') return false;
    if (mode === 'all') return true;
    const before = new Set(current.resourceIds);
    return resourceIds.some((id) => !before.has(id));
  }

  private async readState(key: ResourceScopeKey): Promise<ScopeState> {
    const response = await this.fetchObject(key);
    if (response === null) return { scope: DEFAULT_RESOURCE_SCOPE, etag: undefined };
    if (!response.Body || !response.ETag) throw new ResourceScopeUnavailableError();
    return { scope: await this.open(response.Body, key), etag: response.ETag };
  }

  private async fetchObject(key: ResourceScopeKey): Promise<GetObjectCommandOutput | null> {
    try {
      return await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: this.objectKey(key) }),
      );
    } catch (error) {
      if (error instanceof NoSuchKey) return null;
      throw new ResourceScopeUnavailableError();
    }
  }

  private async open(
    body: NonNullable<GetObjectCommandOutput['Body']>,
    key: ResourceScopeKey,
  ): Promise<ResourceScope> {
    let plaintext: Buffer | undefined;
    try {
      const raw = Buffer.from(await body.transformToByteArray());
      const ciphertext = Buffer.from(raw.toString('utf8'), 'base64');
      raw.fill(0);
      try {
        plaintext = await this.deps.crypto.decryptResourceScope(ciphertext, key);
      } finally {
        ciphertext.fill(0);
      }
      const parsed = resourceScopeSchema.safeParse(JSON.parse(plaintext.toString('utf8')));
      if (!parsed.success) throw new ResourceScopeUnavailableError();
      return parsed.data;
    } catch {
      throw new ResourceScopeUnavailableError();
    } finally {
      plaintext?.fill(0);
    }
  }

  private async persist(
    key: ResourceScopeKey,
    scope: ResourceScope,
    etag: string | undefined,
  ): Promise<void> {
    const plaintext = Buffer.from(JSON.stringify(scope), 'utf8');
    let ciphertext: Buffer;
    try {
      ciphertext = await this.deps.crypto.encryptResourceScope(plaintext, key);
    } catch {
      throw new ResourceScopeUnavailableError();
    } finally {
      plaintext.fill(0);
    }
    try {
      await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: this.deps.bucket,
          Key: this.objectKey(key),
          Body: ciphertext.toString('base64'),
          ContentType: 'application/octet-stream',
          ...(etag ? { IfMatch: etag } : { IfNoneMatch: '*' }),
        }),
      );
    } catch (error) {
      if (isS3ConditionalConflict(error)) throw new ResourceScopeConflictError();
      throw new ResourceScopeUnavailableError();
    } finally {
      ciphertext.fill(0);
    }
  }

  private objectKey(key: ResourceScopeKey): string {
    return `${key.deploymentId}/${RESOURCE_SCOPE_OBJECT_PURPOSE}/${key.sourceKind}/v1.json`;
  }
}
