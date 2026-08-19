import type {
  CodebaseRepositoryPage,
  CodebaseRepositoryPageQuery,
  CodebaseSelectionRequest,
  CodebaseSelectionResponse,
} from '@folklore/contracts';
import type { CodebaseSettingsPort } from '@folklore/api';
import { github } from '@folklore/connectors';
import type { S3Client } from '@aws-sdk/client-s3';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import { resolveSourceToken } from '../pull/pull-runner.js';
import type { DecryptedSourceConnection } from '../pull/source-connections-client.js';
import { CodebaseSelectionStore } from './CodebaseSelectionStore.js';

const PAGE_SIZE = 100;

interface SelectionScope {
  deploymentId: string;
  bucket: string;
  crypto: EnclaveCrypto;
}

interface TenantCodebaseContext {
  crypto: EnclaveCrypto;
  codebaseSelectionScope(): SelectionScope;
}

interface InteractiveConnectionResolver {
  resolve(orgId: string): Promise<{ connection: DecryptedSourceConnection; scope: SelectionScope }>;
}

export interface EnclaveCodebaseSettingsAdapterDeps {
  s3: S3Client;
  resolveTenant(orgId: string): TenantCodebaseContext;
  resolveConnection: InteractiveConnectionResolver['resolve'];
  mintGitHubInstallationToken: (input: {
    installationId: string;
  }) => Promise<{ accessToken: string; expiresAt: string }>;
}

function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
      offset?: unknown;
    };
    if (
      Object.keys(parsed).length !== 1 ||
      !Number.isSafeInteger(parsed.offset) ||
      (parsed.offset as number) < 0
    ) {
      throw new Error('invalid');
    }
    return parsed.offset as number;
  } catch {
    throw new Error('codebase_cursor_invalid');
  }
}

function encodeCursor(offset: number): string {
  return Buffer.from(JSON.stringify({ offset }), 'utf8').toString('base64url');
}

function response(selection: {
  mode: 'all' | 'selected';
  revision: number;
  repositories: readonly { id: number }[];
}): CodebaseSelectionResponse {
  return selection.mode === 'all'
    ? { mode: 'all', revision: selection.revision, repositoryIds: [] }
    : {
        mode: 'selected',
        revision: selection.revision,
        repositoryIds: selection.repositories.map((r) => r.id),
      };
}

export class EnclaveCodebaseSettingsAdapter implements CodebaseSettingsPort {
  constructor(private readonly deps: EnclaveCodebaseSettingsAdapterDeps) {}

  async listRepositories(input: {
    orgId: string;
    query: CodebaseRepositoryPageQuery;
  }): Promise<CodebaseRepositoryPage> {
    const repositories = await this.repositories(input.orgId);
    const offset = decodeCursor(input.query.cursor);
    const query = input.query.query?.toLocaleLowerCase();
    const filtered = query
      ? repositories.filter((repository) =>
          repository.full_name.toLocaleLowerCase().includes(query),
        )
      : repositories;
    const items = filtered
      .slice(offset, offset + PAGE_SIZE)
      .map((repository) => ({ id: repository.id, fullName: repository.full_name }));
    const nextOffset = offset + items.length;
    return { items, nextCursor: nextOffset < filtered.length ? encodeCursor(nextOffset) : null };
  }

  async readSelection(orgId: string): Promise<CodebaseSelectionResponse> {
    const scope = this.deps.resolveTenant(orgId).codebaseSelectionScope();
    try {
      return response(await this.store(scope).read({ orgId, deploymentId: scope.deploymentId }));
    } catch (error) {
      if (error instanceof Error && error.message === 'codebase_selection_missing') {
        return { mode: 'all', revision: 0, repositoryIds: [] };
      }
      throw error;
    }
  }

  async writeSelection(input: {
    orgId: string;
    selection: CodebaseSelectionRequest;
  }): Promise<CodebaseSelectionResponse> {
    const { orgId, selection } = input;
    const { scope } = await this.deps.resolveConnection(orgId);
    const store = this.store(scope);
    const repositories = await this.repositories(orgId);
    if (selection.mode === 'all') {
      return response(
        await store.write({
          orgId,
          deploymentId: scope.deploymentId,
          expectedRevision: selection.expectedRevision,
          mode: 'all',
          repositories: [],
        }),
      );
    }
    const current = new Map(repositories.map((repository) => [repository.id, repository]));
    const selected = selection.repositoryIds.map((id) => current.get(id));
    if (selected.some((repository) => repository === undefined))
      throw new Error('codebase_selection_invalid');
    return response(
      await store.write({
        orgId,
        deploymentId: scope.deploymentId,
        expectedRevision: selection.expectedRevision,
        mode: 'selected',
        repositories: selected.map((repository) => ({
          id: repository!.id,
          fullName: repository!.full_name,
        })),
      }),
    );
  }

  private store(scope: SelectionScope): CodebaseSelectionStore {
    return new CodebaseSelectionStore({
      s3: this.deps.s3,
      bucket: scope.bucket,
      crypto: scope.crypto,
    });
  }

  private async repositories(orgId: string) {
    const { connection } = await this.deps.resolveConnection(orgId);
    let token = await resolveSourceToken(
      'github',
      connection,
      this.deps.mintGitHubInstallationToken,
      { orgId },
    );
    if (!token) throw new Error('github_provider_unavailable');
    try {
      return await new github.OctokitGitHubClient(token).listRepositories();
    } catch {
      throw new Error('github_provider_unavailable');
    } finally {
      token = '';
    }
  }
}
