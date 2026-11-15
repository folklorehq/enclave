import { FREE_PLAN_LIMITS, isFreePlan } from '@folklore/contracts';
import { MS_PER_DAY } from '@folklore/utils/time';
import type { DirectorySourcePort } from '@folklore/wiki';

const DEFAULT_HISTORY_MONTHS = 12;

interface RecordedPlan {
  readonly revision: number;
  readonly free: boolean;
}

/** How far back a tenant's pulls reach, from the last fetched attested plan, RAM only; unknown means the full window. */
export class TenantHistoryWindow {
  private readonly byOrg = new Map<string, RecordedPlan>();

  record(orgId: string, revision: number, plan: string): void {
    const held = this.byOrg.get(orgId);
    if (held && revision < held.revision) return;
    this.byOrg.set(orgId, { revision, free: isFreePlan(plan) });
  }

  // A backfill clears its flag, so before one runs on the free window the plan is read again from the attested source.
  async confirmBeforeBackfill(orgId: string, source: () => DirectorySourcePort): Promise<void> {
    if (!this.byOrg.get(orgId)?.free) return;
    const directory = await source().fetch();
    // No directory is no confirmation: the pull fails and its backfill flag stays set.
    if (directory?.orgId !== orgId) throw new Error('history_window_unconfirmed');
    this.record(orgId, directory.revision, directory.entitlement.plan);
  }

  windowFor(orgId: string, now: Date): Date {
    if (this.byOrg.get(orgId)?.free) {
      return new Date(now.getTime() - FREE_PLAN_LIMITS.historyDays * MS_PER_DAY);
    }
    const since = new Date(now);
    since.setUTCMonth(since.getUTCMonth() - DEFAULT_HISTORY_MONTHS);
    return since;
  }
}
