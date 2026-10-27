import {
  GetObjectCommand,
  ListObjectsV2Command,
  NoSuchKey,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import pLimit from 'p-limit';
import type { CodeGraphNamesRef, EnclaveCrypto } from '../crypto/esdk.js';
import {
  CODE_GRAPH_ERASE_UNAVAILABLE,
  CodeGraphStoreUnavailableError,
  classifyCodeGraphFailure,
} from './code-graph-failure.js';
import { parseShardKey, type ParsedShardKey } from './code-graph-layout.js';

const ERASE_IO_CONCURRENCY = 8;
const ERASED_SHARD = { formatVersion: 1, erased: true, entries: {} } as const;

export interface CodeGraphShardStoreDeps {
  s3: S3Client;
  bucket: string;
  crypto: EnclaveCrypto;
}

/** Reads, lists and overwrites the sealed shard objects of one bucket. */
export class CodeGraphShardStore {
  constructor(private readonly deps: CodeGraphShardStoreDeps) {}

  async listKeys(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    let continuationToken: string | undefined;
    try {
      do {
        const page = await this.deps.s3.send(
          new ListObjectsV2Command({
            Bucket: this.deps.bucket,
            Prefix: prefix,
            ...(continuationToken ? { ContinuationToken: continuationToken } : {}),
          }),
        );
        for (const object of page.Contents ?? []) if (object.Key) keys.push(object.Key);
        continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
      } while (continuationToken);
    } catch {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
    return keys;
  }

  async allErased(orgId: string, keys: string[]): Promise<boolean> {
    const results = await this.boundedMap(keys, (key) => this.isErased(orgId, key));
    return results.every(Boolean);
  }

  async overwriteWithErased(orgId: string, key: string, parsed: ParsedShardKey): Promise<void> {
    const plaintext = Buffer.from(JSON.stringify(ERASED_SHARD), 'utf8');
    let ciphertext: Buffer | undefined;
    try {
      ciphertext = await this.deps.crypto.encryptCodeGraphNames(plaintext, {
        orgId,
        ...this.identity(parsed),
      });
      await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: this.deps.bucket,
          Key: key,
          Body: ciphertext.toString('base64'),
          ContentType: 'application/octet-stream',
        }),
      );
    } catch {
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    } finally {
      plaintext.fill(0);
      ciphertext?.fill(0);
    }
  }

  async boundedMap<T, R>(items: readonly T[], task: (item: T) => Promise<R>): Promise<R[]> {
    const limit = pLimit(ERASE_IO_CONCURRENCY);
    let failed = false;
    return Promise.all(
      items.map((item) =>
        limit(async () => {
          if (failed) throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
          try {
            return await task(item);
          } catch (error) {
            failed = true;
            throw error;
          }
        }),
      ),
    );
  }

  private async isErased(orgId: string, key: string): Promise<boolean> {
    const body = await this.readBody(key);
    if (body === null) return true;
    let plaintext: Buffer;
    try {
      plaintext = await this.deps.crypto.decryptCodeGraphNames(Buffer.from(body, 'base64'), {
        orgId,
        ...this.identity(parseShardKey(orgId, key)),
      });
    } catch (error) {
      if (classifyCodeGraphFailure(error) === 'corrupt') return false;
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
    try {
      return (JSON.parse(plaintext.toString('utf8')) as { erased?: unknown }).erased === true;
    } catch {
      return false;
    } finally {
      plaintext.fill(0);
    }
  }

  private async readBody(key: string): Promise<string | null> {
    try {
      const response = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: key }),
      );
      if (!response.Body) throw new Error('shard_response_incomplete');
      return Buffer.from(await response.Body.transformToByteArray()).toString('utf8');
    } catch (error) {
      if (error instanceof NoSuchKey) return null;
      throw new CodeGraphStoreUnavailableError(CODE_GRAPH_ERASE_UNAVAILABLE);
    }
  }

  private identity(parsed: ParsedShardKey): Omit<CodeGraphNamesRef, 'orgId'> {
    return { generation: parsed.generation, repoNodeId: parsed.repoNodeId, shard: parsed.shard };
  }
}
