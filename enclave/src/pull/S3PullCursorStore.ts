import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { logger } from '../logger.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';

export interface S3PullCursorStoreDeps {
  s3: S3Client;
  crypto: EnclaveCrypto;
  bucket: string;
  orgId: string;
  deploymentId: string;
}

// Sealed `code` and member pull cursors; the worker role can read this bucket but not the plaintext.
export class S3PullCursorStore {
  constructor(private readonly deps: S3PullCursorStoreDeps) {}

  async load(sourceId: string): Promise<string | null> {
    try {
      const object = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: this.objectKey(sourceId) }),
      );
      if (!object.Body) return null;
      const raw = await object.Body.transformToByteArray();
      const ciphertext = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      const plaintext = await this.deps.crypto.decryptPullCursor(ciphertext, {
        orgId: this.deps.orgId,
        sourceId,
      });
      return plaintext.toString('utf8');
    } catch (err) {
      if (err instanceof NoSuchKey) return null;
      // Any other read failure (decrypt mismatch, corrupt blob) re-snapshots budget-capped
      // instead of wedging the pull; the log is count-only, never cursor content.
      logger.warn('sealed pull-cursor: load failed, treating as fresh', {
        error: err instanceof Error ? err.name : 'unknown',
      });
      return null;
    }
  }

  async save(sourceId: string, value: string | null): Promise<void> {
    if (value === null) return;
    const ciphertext = await this.deps.crypto.encryptPullCursor(Buffer.from(value, 'utf8'), {
      orgId: this.deps.orgId,
      sourceId,
    });
    await this.deps.s3.send(
      new PutObjectCommand({
        Bucket: this.deps.bucket,
        Key: this.objectKey(sourceId),
        Body: ciphertext.toString('base64'),
        ContentType: 'text/plain',
      }),
    );
  }

  private objectKey(sourceId: string): string {
    return `${this.deps.deploymentId}/pull-cursor/${sourceId}.json`;
  }
}
