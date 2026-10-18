import type { Logger } from '@folklore/core';
import {
  memberIdentityLinkOutputSchema,
  type MemberIdentityLinkOutput,
  type PendingMemberIdentityLink,
} from '@folklore/contracts';
import { partitionSourceIdentityClaims } from '@folklore/utils';

const HOUR_MS = 60 * 60_000;
const EMIT_FAILED = 'member_link_emit_failed';

export type MemberLinkRelayOutcome = 'acked' | 'emitted' | 'idle' | 'database_unavailable';
export const MEMBER_LINK_SETTLED_OUTCOMES: ReadonlySet<MemberLinkRelayOutcome> = new Set([
  'acked',
  'idle',
]);
export const MEMBER_LINK_MAX_BACKOFF_MS = 6 * HOUR_MS;

export interface MemberIdentityLinkSourcePort {
  list(): Promise<PendingMemberIdentityLink[]>;
  ack(ids: readonly string[]): Promise<void>;
}

export interface MemberIdentityLinkAppliedReaderPort {
  /** Ids of the links the worker has already applied; the literal when no database is live. */
  appliedIds(
    orgId: string,
    links: readonly PendingMemberIdentityLink[],
  ): Promise<string[] | 'database_unavailable'>;
}

export interface MemberIdentityLinkRelayDeps {
  readonly reader: MemberIdentityLinkAppliedReaderPort;
  readonly emit: (output: MemberIdentityLinkOutput) => Promise<void>;
  readonly logger: Logger;
}

/** Carries one tenant's confirmed member links to the worker as signed outputs, acking each once it has applied. */
export class MemberIdentityLinkRelay {
  constructor(private readonly deps: MemberIdentityLinkRelayDeps) {}

  async relay(
    orgId: string,
    source: MemberIdentityLinkSourcePort,
  ): Promise<MemberLinkRelayOutcome> {
    const pending = (await source.list()).filter((link) => link.orgId === orgId);
    const claims = this.unambiguousClaims(pending);
    if (claims.length === 0) return 'idle';
    const applied = await this.deps.reader.appliedIds(orgId, claims);
    if (applied === 'database_unavailable') return applied;
    if (applied.length > 0) await source.ack(applied);
    const unapplied = claims.filter((link) => !applied.includes(link.id));
    const failed = await this.emitAll(unapplied);
    this.deps.logger.info('member_identity_link_relay_pass', {
      orgId,
      acked: applied.length,
      emitted: unapplied.length - failed,
    });
    if (failed > 0) throw new Error(EMIT_FAILED);
    if (applied.length > 0) return 'acked';
    return unapplied.length > 0 ? 'emitted' : 'idle';
  }

  private unambiguousClaims(pending: readonly PendingMemberIdentityLink[]) {
    const { unambiguous, ambiguous } = partitionSourceIdentityClaims(pending);
    for (const group of ambiguous) {
      this.deps.logger.warn('member_identity_link_claims_ambiguous', { count: group.length });
    }
    return unambiguous;
  }

  private async emitAll(links: readonly PendingMemberIdentityLink[]): Promise<number> {
    let failed = 0;
    for (const link of links) {
      if (!(await this.emitOne(link))) failed += 1;
    }
    if (failed > 0) this.deps.logger.warn('member_identity_link_emit_failed', { count: failed });
    return failed;
  }

  private async emitOne(link: PendingMemberIdentityLink): Promise<boolean> {
    const output = memberIdentityLinkOutputSchema.safeParse({
      type: 'member_identity_link',
      orgId: link.orgId,
      linkId: link.id,
      kind: link.kind,
      sourceUserId: link.sourceUserId,
      memberEmail: link.memberEmail,
    });
    if (!output.success) return false;
    try {
      await this.deps.emit(output.data);
      return true;
    } catch {
      return false;
    }
  }
}
