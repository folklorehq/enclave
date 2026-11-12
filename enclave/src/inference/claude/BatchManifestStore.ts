import { createHmac } from 'node:crypto';
import {
  GetObjectCommand,
  ListObjectsV2Command,
  NoSuchKey,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import type { Logger } from '@folklore/core';
import type { EnclaveCrypto } from '../../crypto/esdk.js';
import { isS3ConditionalConflict } from '../../storage/s3-conditional.js';
import { batchLog, type ManifestRefusal } from './batch-log.js';
import { batchManifestSchema, type BatchManifest } from './batch-manifest.js';

const MANIFEST_PREFIX = 'batch-manifests/v1/';
const NAME_LABEL = 'batch-manifest';
const FIRST_VERSION = 1;

export class BatchManifestRolledBackError extends Error {
  constructor() {
    super('batch_manifest_rolled_back');
    this.name = 'BatchManifestRolledBackError';
  }
}

export class BatchManifestConflictError extends Error {
  constructor() {
    super('batch_manifest_conflict');
    this.name = 'BatchManifestConflictError';
  }
}

/** A manifest as read, with the object version a conditional write must still find. */
export interface GuardedManifest {
  readonly manifest: BatchManifest | undefined;
  readonly etag: string | undefined;
}

interface StoredObject {
  readonly sealed: Buffer;
  readonly etag: string | undefined;
}

export interface BatchStorageScope {
  readonly crypto: Pick<EnclaveCrypto, 'encryptBatchManifest' | 'decryptBatchManifest'>;
  readonly bucket: string;
  readonly nameKey: Buffer;
}

export interface BatchManifestStoreDeps {
  readonly s3: Pick<S3Client, 'send'>;
  readonly orgId: string;
  readonly scope: () => BatchStorageScope;
  readonly logger?: Logger;
}

/** One org's sealed batch manifests, named by a keyed digest of the request id under their own listable prefix. */
export class BatchManifestStore {
  private readonly highestSeen = new Map<string, number>();
  // Closed manifests are never deleted, so a listing skips the ones this process has already seen closed.
  private readonly closedKeys = new Set<string>();

  constructor(private readonly deps: BatchManifestStoreDeps) {}

  async read(wikiRequestId: string): Promise<BatchManifest | undefined> {
    return (await this.readGuarded(wikiRequestId)).manifest;
  }

  async readGuarded(wikiRequestId: string): Promise<GuardedManifest> {
    const stored = await this.fetch(this.keyFor(wikiRequestId));
    if (stored !== undefined) {
      return { manifest: await this.open(stored.sealed, wikiRequestId), etag: stored.etag };
    }
    if (!this.highestSeen.has(wikiRequestId)) return { manifest: undefined, etag: undefined };
    this.refused('deleted');
    throw new BatchManifestRolledBackError();
  }

  /** True when a conditional write can be held to the object the basis read. */
  canGuard(basis: GuardedManifest): boolean {
    return basis.manifest === undefined || basis.etag !== undefined;
  }

  /** With a basis, the write lands only if the object is still the one that basis read. */
  async write(manifest: BatchManifest, basis?: GuardedManifest): Promise<void> {
    const scope = this.deps.scope();
    const version = (this.highestSeen.get(manifest.wikiRequestId) ?? 0) + FIRST_VERSION;
    const sealed = await scope.crypto.encryptBatchManifest(
      Buffer.from(JSON.stringify(manifest), 'utf8'),
      { orgId: this.deps.orgId, wikiRequestId: manifest.wikiRequestId, version },
    );
    const put = new PutObjectCommand({
      Bucket: scope.bucket,
      Key: this.keyFor(manifest.wikiRequestId),
      Body: sealed.toString('base64'),
      ContentType: 'application/octet-stream',
      ...this.preconditionOf(basis),
    });
    try {
      await this.deps.s3.send(put);
    } catch (error) {
      if (isS3ConditionalConflict(error)) throw new BatchManifestConflictError();
      throw error;
    }
    this.highestSeen.set(manifest.wikiRequestId, version);
    this.noteState(manifest);
  }

  async listOpen(): Promise<BatchManifest[]> {
    const manifests: BatchManifest[] = [];
    for (const key of await this.listKeys()) {
      if (this.closedKeys.has(key)) continue;
      const manifest = await this.openListed(key);
      if (manifest !== undefined && !manifest.closed) manifests.push(manifest);
    }
    return manifests;
  }

  private preconditionOf(basis: GuardedManifest | undefined): {
    IfMatch?: string;
    IfNoneMatch?: string;
  } {
    if (basis === undefined) return {};
    if (basis.manifest === undefined) return { IfNoneMatch: '*' };
    if (basis.etag === undefined) throw new BatchManifestConflictError();
    return { IfMatch: basis.etag };
  }

  private async openListed(key: string): Promise<BatchManifest | undefined> {
    try {
      const stored = await this.fetch(key);
      const manifest = stored === undefined ? undefined : await this.open(stored.sealed);
      if (manifest === undefined || this.keyFor(manifest.wikiRequestId) !== key) {
        this.refused('foreign_name');
        return undefined;
      }
      return manifest;
    } catch (error) {
      this.refused(error instanceof BatchManifestRolledBackError ? 'rolled_back' : 'unreadable');
      return undefined;
    }
  }

  private async open(sealed: Buffer, wikiRequestId?: string): Promise<BatchManifest> {
    const opened = await this.deps.scope().crypto.decryptBatchManifest(sealed, {
      orgId: this.deps.orgId,
      ...(wikiRequestId === undefined ? {} : { wikiRequestId }),
    });
    const manifest = batchManifestSchema.parse(JSON.parse(opened.plaintext.toString('utf8')));
    if (manifest.orgId !== this.deps.orgId || manifest.wikiRequestId !== opened.wikiRequestId) {
      throw new Error('batch_manifest_identity_mismatch');
    }
    this.assertNotRolledBack(manifest.wikiRequestId, opened.version);
    this.noteState(manifest);
    return manifest;
  }

  private noteState(manifest: BatchManifest): void {
    const key = this.keyFor(manifest.wikiRequestId);
    if (manifest.closed) this.closedKeys.add(key);
    else this.closedKeys.delete(key);
  }

  private assertNotRolledBack(wikiRequestId: string, version: number): void {
    const seen = this.highestSeen.get(wikiRequestId) ?? 0;
    if (version < seen) {
      this.refused('rolled_back');
      throw new BatchManifestRolledBackError();
    }
    this.highestSeen.set(wikiRequestId, version);
  }

  private async fetch(key: string): Promise<StoredObject | undefined> {
    try {
      const object = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.scope().bucket, Key: key }),
      );
      const raw = await object.Body?.transformToByteArray();
      if (raw === undefined) return undefined;
      const sealed = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      return { sealed, etag: object.ETag };
    } catch (error) {
      if (error instanceof NoSuchKey) return undefined;
      throw error;
    }
  }

  private async listKeys(): Promise<string[]> {
    const keys: string[] = [];
    let token: string | undefined;
    do {
      const page = await this.deps.s3.send(
        new ListObjectsV2Command({
          Bucket: this.deps.scope().bucket,
          Prefix: this.prefix(),
          ...(token === undefined ? {} : { ContinuationToken: token }),
        }),
      );
      for (const object of page.Contents ?? []) if (object.Key) keys.push(object.Key);
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token !== undefined);
    return keys;
  }

  private keyFor(wikiRequestId: string): string {
    const name = createHmac('sha256', this.deps.scope().nameKey)
      .update(`${NAME_LABEL}:${wikiRequestId}`)
      .digest('hex');
    return `${this.prefix()}${name}`;
  }

  private prefix(): string {
    return `${MANIFEST_PREFIX}${this.deps.orgId}/`;
  }

  private refused(reason: ManifestRefusal): void {
    this.deps.logger?.warn(...batchLog.manifestRefused(reason));
  }
}
