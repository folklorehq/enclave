import type { PendingMemberIdentityLink } from '@folklore/contracts';
import { MemberLinkAppliedRepository, type MemberLinkAppliedRepositoryPort } from '@folklore/wiki';
import type { MemberIdentityLinkAppliedReaderPort } from './MemberIdentityLinkRelay.js';

export interface MemberIdentityLinkDatabase {
  readonly orm: ConstructorParameters<typeof MemberLinkAppliedRepository>[0];
}

/** Reads whether the worker has already applied a member link, through the runtime database lease that is live now. */
export class MemberIdentityLinkAppliedReader implements MemberIdentityLinkAppliedReaderPort {
  constructor(
    private readonly database: () => MemberIdentityLinkDatabase | undefined,
    private readonly lookupOver: (
      database: MemberIdentityLinkDatabase,
    ) => MemberLinkAppliedRepositoryPort = (database) =>
      new MemberLinkAppliedRepository(database.orm),
  ) {}

  async appliedIds(
    orgId: string,
    links: readonly PendingMemberIdentityLink[],
  ): Promise<string[] | 'database_unavailable'> {
    const database = this.database();
    if (!database) return 'database_unavailable';
    return this.lookupOver(database).appliedIds(orgId, links);
  }
}
