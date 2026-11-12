import { z } from 'zod';

const requestSchema = z
  .object({
    customId: z.string(),
    model: z.string(),
    purpose: z.string(),
    operation: z.enum(['generate', 'structured']),
  })
  .strict();

const cancelPurposeSchema = z.enum(['drain', 'discard']);

const snapshotSchema = z
  .object({
    audienceId: z.string().nullable(),
    facts: z.array(z.tuple([z.string(), z.string()])),
  })
  .strict();

export const batchManifestSchema = z
  .object({
    v: z.literal(1),
    orgId: z.string(),
    wikiRequestId: z.string(),
    closed: z.boolean(),
    rounds: z.number().int().nonnegative(),
    startedAtMs: z.number().int().nonnegative(),
    open: z
      .object({
        batchId: z.string(),
        requests: z.array(requestSchema),
        cancelRequested: z.boolean().optional(),
        cancelPurpose: cancelPurposeSchema.optional(),
      })
      .strict()
      .optional(),
    resultIds: z.array(z.string()),
    snapshot: z.array(snapshotSchema),
  })
  .strict();

export type CancelPurpose = z.infer<typeof cancelPurposeSchema>;
export type BatchManifest = z.infer<typeof batchManifestSchema>;

export function isUnclosedManifest(manifest: BatchManifest | undefined): manifest is BatchManifest {
  return manifest !== undefined && !manifest.closed;
}
export type BatchManifestRequest = z.infer<typeof requestSchema>;
export type BatchSnapshotAudience = z.infer<typeof snapshotSchema>;
