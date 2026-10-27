import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import {
  CODE_GRAPH_TOMBSTONE_UNAVAILABLE,
  CodeGraphObjectCorruptError,
  CodeGraphStoreUnavailableError,
  classifyCodeGraphFailure,
} from './code-graph-failure.js';
import { codeGraphTombstoneKey } from './code-graph-layout.js';
import { codeGraphTombstoneSchema, type CodeGraphTombstone } from './code-graph-tombstone.js';

const CONDITIONAL_CONFLICT_STATUSES: ReadonlySet<number> = new Set([409, 412]);
const CONDITIONAL_CONFLICT_NAMES: ReadonlySet<string> = new Set([
  'PreconditionFailed',
  'ConditionalRequestConflict',
]);

export type TombstoneRead =
  | { kind: 'missing' }
  | { kind: 'ok'; tombstone: CodeGraphTombstone; etag: string }
  | { kind: 'corrupt'; etag: string };

export interface CodeGraphTombstoneStoreDeps {
  s3: S3Client;
  bucket: string;
  crypto: EnclaveCrypto;
}

export class CodeGraphTombstoneStore {
  constructor(private readonly deps: CodeGraphTombstoneStoreDeps) {}

  async read(orgId: string): Promise<TombstoneRead> {
    const fetched = await this.fetch(orgId);
    if (fetched === null) return { kind: 'missing' };
    try {
      return { kind: 'ok', tombstone: await this.open(orgId, fetched.body), etag: fetched.etag };
    } catch (error) {
      if (classifyCodeGraphFailure(error) === 'corrupt')
        return { kind: 'corrupt', etag: fetched.etag };
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_TOMBSTONE_UNAVAILABLE);
    }
  }

  async write(
    orgId: string,
    tombstone: CodeGraphTombstone,
    etag: string | null,
  ): Promise<'written' | 'conflict'> {
    const ciphertext = await this.seal(orgId, tombstone);
    try {
      await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: this.deps.bucket,
          Key: codeGraphTombstoneKey(orgId),
          Body: ciphertext.toString('base64'),
          ContentType: 'application/octet-stream',
          ...(etag === null ? { IfNoneMatch: '*' } : { IfMatch: etag }),
        }),
      );
      return 'written';
    } catch (error) {
      if (this.isConditionalConflict(error)) return 'conflict';
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_TOMBSTONE_UNAVAILABLE);
    } finally {
      ciphertext.fill(0);
    }
  }

  private async fetch(orgId: string): Promise<{ body: string; etag: string } | null> {
    try {
      const response = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: codeGraphTombstoneKey(orgId) }),
      );
      if (!response.Body || !response.ETag) throw new Error('tombstone_response_incomplete');
      const bytes = await response.Body.transformToByteArray();
      return { body: Buffer.from(bytes).toString('utf8'), etag: response.ETag };
    } catch (error) {
      if (error instanceof NoSuchKey) return null;
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_TOMBSTONE_UNAVAILABLE);
    }
  }

  private async open(orgId: string, body: string): Promise<CodeGraphTombstone> {
    const ciphertext = Buffer.from(body, 'base64');
    const plaintext = await this.deps.crypto.decryptCodeGraphTombstone(ciphertext, { orgId });
    try {
      const parsed = codeGraphTombstoneSchema.safeParse(JSON.parse(plaintext.toString('utf8')));
      if (!parsed.success) throw new CodeGraphObjectCorruptError();
      return parsed.data;
    } catch {
      throw new CodeGraphObjectCorruptError();
    } finally {
      plaintext.fill(0);
    }
  }

  private async seal(orgId: string, tombstone: CodeGraphTombstone): Promise<Buffer> {
    const plaintext = Buffer.from(JSON.stringify(tombstone), 'utf8');
    try {
      return await this.deps.crypto.encryptCodeGraphTombstone(plaintext, { orgId });
    } catch {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_TOMBSTONE_UNAVAILABLE);
    } finally {
      plaintext.fill(0);
    }
  }

  private isConditionalConflict(error: unknown): boolean {
    if (!error || typeof error !== 'object') return false;
    const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
    const status = candidate.$metadata?.httpStatusCode;
    return (
      (typeof candidate.name === 'string' && CONDITIONAL_CONFLICT_NAMES.has(candidate.name)) ||
      (typeof status === 'number' && CONDITIONAL_CONFLICT_STATUSES.has(status))
    );
  }
}
