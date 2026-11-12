import type { DirectorySync } from '@folklore/contracts';
import { contentFreeErrorType, isFailureCodeSlug, type Logger } from '@folklore/core';
import {
  EntitlementProjectionRepository,
  EntitlementProjectionService,
  MemberAskChatPurgeRepository,
  TeamProjectionRepository,
  type DirectorySourcePort,
  type EntitlementSyncOutcome,
} from '@folklore/wiki';
import type { TelemetryClient } from '@folklore/telemetry';
import { DirectoryRejectionReporter } from './DirectoryRejectionReporter.js';
import { TeamProjectionFailureReporter } from './TeamProjectionFailureReporter.js';
import type { TenantBatchConsent } from './TenantBatchConsent.js';
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
  readonly batchConsent?: TenantBatchConsent;
  readonly onBatchNotAllowed?: (orgId: string) => Promise<unknown>;
  readonly opsTelemetry?: TelemetryClient;
  readonly now?: () => number;
  readonly createService?: (
    source: DirectorySourcePort,
    database: ProjectionDatabase,
  ) => EntitlementProjectionSync;
}

/** Writes a tenant's directory projection through the runtime database lease that is live now. */
export class EntitlementProjectionApplier {
  private readonly createService: NonNullable<EntitlementProjectionApplierDeps['createService']>;

  private readonly teamFailures: TeamProjectionFailureReporter | null;

  private readonly directoryRejections: DirectoryRejectionReporter | null;

  constructor(private readonly deps: EntitlementProjectionApplierDeps) {
    const now = deps.now ?? (() => performance.now());
    this.teamFailures = deps.opsTelemetry
      ? new TeamProjectionFailureReporter(deps.opsTelemetry, now)
      : null;
    this.directoryRejections = deps.opsTelemetry
      ? new DirectoryRejectionReporter(deps.opsTelemetry, now)
      : null;
    this.createService =
      deps.createService ?? ((source, database) => this.service(source, database));
  }

  async apply(orgId: string, source: DirectorySourcePort): Promise<TenantProjectionOutcome> {
    const database = this.deps.database();
    if (!database) return 'database_unavailable';
    const seen: { directory?: DirectorySync } = {};
    const outcome = await this.createService(
      this.observed(orgId, source, (directory) => (seen.directory = directory)),
      database,
    ).sync();
    if (outcome === 'applied' && seen.directory) {
      this.recordConsent(orgId, seen.directory);
      await this.cancelBatchesWithoutConsent(orgId, seen.directory);
    }
    return outcome;
  }

  // Decided from the applied state alone, so a restart between two passes cannot skip it.
  private async cancelBatchesWithoutConsent(
    orgId: string,
    directory: DirectorySync,
  ): Promise<void> {
    if (directory.orgId !== orgId || directory.entitlement.batchAllowed === true) return;
    try {
      await this.deps.onBatchNotAllowed?.(orgId);
    } catch {
      this.deps.logger.warn('batch_opt_out_cancel_failed', {});
    }
  }

  // Consent comes only from a projection that was applied, so a stale or rejected pass never moves it.
  private recordConsent(orgId: string, directory: DirectorySync): void {
    if (directory.orgId !== orgId) return;
    this.deps.batchConsent?.record(orgId, directory.revision, directory.entitlement.batchAllowed);
  }

  // The service folds every fetch failure into 'unavailable'; the fixed code is what tells an org
  // mismatch apart from a missing directory.
  private observed(
    orgId: string,
    source: DirectorySourcePort,
    onFetched: (directory: DirectorySync) => void,
  ): DirectorySourcePort {
    return {
      fetch: async () => {
        try {
          const directory = await source.fetch();
          if (directory) onFetched(directory);
          return directory;
        } catch (err) {
          this.logSourceFailure(orgId, err);
          this.directoryRejections?.observe(err);
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
    const teams = new TeamProjectionRepository(database.orm);
    return new EntitlementProjectionService(
      source,
      new EntitlementProjectionRepository(database.orm),
      this.deps.logger,
      undefined,
      new MemberAskChatPurgeRepository(database.orm),
      this.teamFailures?.reporting(teams) ?? teams,
    );
  }
}
