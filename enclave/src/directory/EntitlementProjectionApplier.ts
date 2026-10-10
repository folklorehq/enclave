import { contentFreeErrorType, isFailureCodeSlug, type Logger } from '@folklore/core';
import {
  EntitlementProjectionRepository,
  EntitlementProjectionService,
  type DirectorySourcePort,
  type EntitlementSyncOutcome,
} from '@folklore/wiki';
import type { TenantProjectionOutcome } from './TenantEntitlementProjectionRunner.js';

export interface ProjectionDatabase {
  readonly orm: ConstructorParameters<typeof EntitlementProjectionRepository>[0];
}

export interface EntitlementProjectionSync {
  sync(): Promise<EntitlementSyncOutcome>;
}

export interface EntitlementProjectionApplierDeps {
  readonly database: () => ProjectionDatabase | undefined;
  readonly logger: Logger;
  readonly createService?: (
    source: DirectorySourcePort,
    database: ProjectionDatabase,
  ) => EntitlementProjectionSync;
}

/** Writes a tenant's directory projection through the runtime database lease that is live now. */
export class EntitlementProjectionApplier {
  private readonly createService: NonNullable<EntitlementProjectionApplierDeps['createService']>;

  constructor(private readonly deps: EntitlementProjectionApplierDeps) {
    this.createService =
      deps.createService ?? ((source, database) => this.service(source, database));
  }

  async apply(orgId: string, source: DirectorySourcePort): Promise<TenantProjectionOutcome> {
    const database = this.deps.database();
    if (!database) return 'database_unavailable';
    return this.createService(this.observed(orgId, source), database).sync();
  }

  // The service folds every fetch failure into 'unavailable'; the fixed code is what tells an org
  // mismatch apart from a missing directory.
  private observed(orgId: string, source: DirectorySourcePort): DirectorySourcePort {
    return {
      fetch: async () => {
        try {
          return await source.fetch();
        } catch (err) {
          this.logSourceFailure(orgId, err);
          throw err;
        }
      },
    };
  }

  private logSourceFailure(orgId: string, err: unknown): void {
    const message = err instanceof Error ? err.message : undefined;
    this.deps.logger.warn('entitlement_projection_source_failed', {
      orgId,
      errorCode: isFailureCodeSlug(message) ? message : null,
      error_type: contentFreeErrorType(err),
    });
  }

  private service(
    source: DirectorySourcePort,
    database: ProjectionDatabase,
  ): EntitlementProjectionSync {
    return new EntitlementProjectionService(
      source,
      new EntitlementProjectionRepository(database.orm),
      this.deps.logger,
    );
  }
}
