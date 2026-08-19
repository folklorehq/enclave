import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { z } from 'zod';
import type { EnclaveCrypto } from '../crypto/esdk.js';

const CODEBASE_SELECTION_FORMAT_VERSION = 1;
const CODEBASE_SELECTION_PURPOSE = 'codebase-selection';
const CODEBASE_SELECTION_MAX_REPOSITORIES = 500;

export const repositoryRefSchema = z
  .object({
    id: z.number().int().positive(),
    fullName: z.string().min(1).max(512),
  })
  .strict();

export const codebaseSelectionSchema = z.discriminatedUnion('mode', [
  z
    .object({
      formatVersion: z.literal(CODEBASE_SELECTION_FORMAT_VERSION),
      revision: z.number().int().nonnegative(),
      mode: z.literal('all'),
      repositories: z.tuple([]),
    })
    .strict(),
  z
    .object({
      formatVersion: z.literal(CODEBASE_SELECTION_FORMAT_VERSION),
      revision: z.number().int().nonnegative(),
      mode: z.literal('selected'),
      repositories: z.array(repositoryRefSchema).min(1).max(CODEBASE_SELECTION_MAX_REPOSITORIES),
    })
    .strict(),
]);

const codebaseSelectionWriteSchema = z.discriminatedUnion('mode', [
  z
    .object({
      orgId: z.string().min(1),
      deploymentId: z.string().min(1),
      expectedRevision: z.number().int().nonnegative(),
      mode: z.literal('all'),
      repositories: z.tuple([]),
    })
    .strict(),
  z
    .object({
      orgId: z.string().min(1),
      deploymentId: z.string().min(1),
      expectedRevision: z.number().int().nonnegative(),
      mode: z.literal('selected'),
      repositories: z.array(repositoryRefSchema).min(1).max(CODEBASE_SELECTION_MAX_REPOSITORIES),
    })
    .strict(),
]);

export type RepositoryRef = z.infer<typeof repositoryRefSchema>;
export type CodebaseSelection = z.infer<typeof codebaseSelectionSchema>;
export type CodebaseSelectionWrite = z.infer<typeof codebaseSelectionWriteSchema>;

export interface CodebaseSelectionStoreDeps {
  s3: S3Client;
  bucket: string;
  crypto: EnclaveCrypto;
}

export class CodebaseSelectionConflictError extends Error {
  constructor() {
    super('codebase_selection_conflict');
    this.name = 'CodebaseSelectionConflictError';
  }
}

interface SelectionState {
  selection: CodebaseSelection;
  etag: string;
}

/** Stores the codebase repository allowlist only as tenant-bound ESDK ciphertext. */
export class CodebaseSelectionStore {
  constructor(private readonly deps: CodebaseSelectionStoreDeps) {}

  async read(input: { orgId: string; deploymentId: string }): Promise<CodebaseSelection> {
    return (await this.readState(input)).selection;
  }

  async write(input: CodebaseSelectionWrite): Promise<CodebaseSelection> {
    const parsed = codebaseSelectionWriteSchema.safeParse(input);
    if (!parsed.success) throw new Error('codebase_selection_invalid');
    const selection = this.normalize(parsed.data);
    let state: SelectionState | null;
    try {
      state = await this.readState(selection);
    } catch (error) {
      if (!this.isMissing(error)) throw error;
      state = null;
    }
    if (selection.expectedRevision !== (state?.selection.revision ?? 0)) {
      throw new CodebaseSelectionConflictError();
    }
    const next = this.nextSelection(selection, selection.expectedRevision + 1);
    await this.persist(selection, next, state?.etag);
    return next;
  }

  private async readState(input: { orgId: string; deploymentId: string }): Promise<SelectionState> {
    try {
      const response = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.bucket, Key: this.objectKey(input.deploymentId) }),
      );
      if (!response.Body || !response.ETag) throw new Error('codebase_selection_unavailable');
      const raw = Buffer.from(await response.Body.transformToByteArray());
      const ciphertext = Buffer.from(raw.toString('utf8'), 'base64');
      raw.fill(0);
      let plaintext: Buffer;
      try {
        plaintext = await this.deps.crypto.decryptCodebaseSelection(ciphertext, input);
      } catch {
        throw new Error('codebase_selection_unavailable');
      } finally {
        ciphertext.fill(0);
      }
      try {
        const parsed = codebaseSelectionSchema.safeParse(JSON.parse(plaintext.toString('utf8')));
        if (!parsed.success) throw new Error('codebase_selection_unavailable');
        return { selection: parsed.data, etag: response.ETag };
      } catch (error) {
        if (this.isUnavailable(error)) throw error;
        throw new Error('codebase_selection_unavailable');
      } finally {
        plaintext.fill(0);
      }
    } catch (error) {
      if (error instanceof NoSuchKey) throw new Error('codebase_selection_missing');
      if (this.isMissing(error) || this.isUnavailable(error)) throw error;
      throw new Error('codebase_selection_unavailable');
    }
  }

  private async persist(
    input: { orgId: string; deploymentId: string },
    selection: CodebaseSelection,
    etag: string | undefined,
  ): Promise<void> {
    const plaintext = Buffer.from(JSON.stringify(selection), 'utf8');
    let ciphertext: Buffer;
    try {
      ciphertext = await this.deps.crypto.encryptCodebaseSelection(plaintext, input);
    } finally {
      plaintext.fill(0);
    }
    try {
      const response = await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: this.deps.bucket,
          Key: this.objectKey(input.deploymentId),
          Body: ciphertext.toString('base64'),
          ContentType: 'application/octet-stream',
          ...(etag ? { IfMatch: etag } : { IfNoneMatch: '*' }),
        }),
      );
      if (!response.ETag) throw new Error('codebase_selection_unavailable');
    } catch (error) {
      if (this.isConditionalConflict(error)) throw new CodebaseSelectionConflictError();
      if (this.isUnavailable(error)) throw error;
      throw new Error('codebase_selection_unavailable');
    } finally {
      ciphertext.fill(0);
    }
  }

  private normalize(input: CodebaseSelectionWrite): CodebaseSelectionWrite {
    if (input.mode === 'all') return input;
    const repositories = new Map<number, RepositoryRef>();
    for (const repository of input.repositories) repositories.set(repository.id, repository);
    const deduplicated = [...repositories.values()].sort((left, right) => left.id - right.id);
    if (deduplicated.length === 0 || deduplicated.length > CODEBASE_SELECTION_MAX_REPOSITORIES) {
      throw new Error('codebase_selection_invalid');
    }
    return { ...input, repositories: deduplicated };
  }

  private nextSelection(input: CodebaseSelectionWrite, revision: number): CodebaseSelection {
    if (input.mode === 'all') {
      return {
        formatVersion: CODEBASE_SELECTION_FORMAT_VERSION,
        revision,
        mode: 'all',
        repositories: [],
      };
    }
    return {
      formatVersion: CODEBASE_SELECTION_FORMAT_VERSION,
      revision,
      mode: 'selected',
      repositories: input.repositories,
    };
  }

  private objectKey(deploymentId: string): string {
    return `${deploymentId}/${CODEBASE_SELECTION_PURPOSE}/v1.json`;
  }

  private isMissing(error: unknown): boolean {
    return error instanceof Error && error.message === 'codebase_selection_missing';
  }

  private isUnavailable(error: unknown): boolean {
    return error instanceof Error && error.message === 'codebase_selection_unavailable';
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
