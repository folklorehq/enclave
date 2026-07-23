import type { S3Client } from '@aws-sdk/client-s3';
import type { Logger } from '@folklore/core';
import type { TenantContext } from './tenant-context.js';

// HNSW only auto-persists every SAVE_INTERVAL inserts, so shutdown must flush every tenant's
// in-RAM window on scale-to-zero. One tenant's save failure must not strand the others, so each
// is isolated; the log is content-free (tenant id only, ADL #18).
export async function saveAllTenantIndices(
  contexts: TenantContext[],
  s3: S3Client,
  bucket: string,
  logger: Logger,
): Promise<void> {
  await Promise.all(
    contexts.map(async (context) => {
      try {
        await context.hnsw.save(s3, context.keyring, bucket, context.tenantId);
      } catch {
        logger.error('HNSW_SAVE_FAILED', { tenant: context.tenantId });
      }
    }),
  );
}
