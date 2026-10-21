import { ExportedPageRefRepository, type ExportedPageRefRepositoryPort } from '@folklore/wiki';

export interface ExportedPageRefDatabase {
  readonly orm: ConstructorParameters<typeof ExportedPageRefRepository>[0];
}

export interface ExportedPageRefReaderPort {
  notionPageIds(orgId: string): Promise<ReadonlySet<string> | 'database_unavailable'>;
}

/** Reads the ids of pages the product created in the org's Notion, through the runtime database lease that is live now. */
export class ExportedPageRefReader implements ExportedPageRefReaderPort {
  constructor(
    private readonly database: () => ExportedPageRefDatabase | undefined,
    private readonly lookupOver: (
      database: ExportedPageRefDatabase,
    ) => ExportedPageRefRepositoryPort = (database) => new ExportedPageRefRepository(database.orm),
  ) {}

  async notionPageIds(orgId: string): Promise<ReadonlySet<string> | 'database_unavailable'> {
    const database = this.database();
    if (!database) return 'database_unavailable';
    return new Set(await this.lookupOver(database).notionPageIds(orgId));
  }
}
