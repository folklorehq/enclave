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

// ESDK-sealed `code` connector cursors in the tenant's processed bucket — the SSM path is
// 4 KB Standard-tier capped and the cursor grows monotonically with install size. The worker
// Lambda role can read this bucket, so nothing here is plaintext-readable without the tenant
// keyring (same pattern as S3LlmCache).
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
      logger.warn('code pull-cursor: load failed, treating as fresh', {
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
