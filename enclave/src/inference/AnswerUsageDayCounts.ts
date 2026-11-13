import type { AskUsageAttribution } from '@folklore/api';
import {
  USAGE_LOG_COST_BUCKET_MICROS,
  usageCostMicros,
  type AskUsageSurface,
} from '@folklore/contracts';
import { paidCallsOf, type TokenUsage } from '@folklore/contracts/enclave';
import type { Logger } from '@folklore/core';
import { roundUpTo } from '@folklore/utils';
import { MS_PER_DAY, utcDayKey, utcDayStart } from '@folklore/utils/time';

export const ANSWER_USAGE_MAX_ROWS = 10_000;

const ANSWER_USAGE_DAILY_EVENT = 'answer_usage_daily';
const ANSWER_USAGE_DROPPED_EVENT = 'answer_usage_daily_dropped';
const KEY_SEPARATOR = '|';
const ORG_ONLY_SURFACE: AskUsageSurface = 'page_rewrite';

interface SurfaceDay {
  readonly orgId: string;
  readonly surface: AskUsageSurface;
  readonly dayStart: number;
  costMicros: number;
  calls: number;
}

/** An org's priced spend per surface and UTC day is logged once the day has ended, never per run or per member; the cost rounds up to a cent, the calls stay exact. */
export class AnswerUsageDayCounts {
  private readonly rows = new Map<string, SurfaceDay>();
  private dropped = 0;

  constructor(private readonly deps: { readonly logger: Logger; readonly now?: () => number }) {}

  add(subject: AskUsageAttribution, usage: readonly TokenUsage[]): void {
    const paid = usage.filter((entry) => paidCallsOf(entry) > 0);
    if (paid.length === 0) return;
    const calls = paid.reduce((sum, entry) => sum + paidCallsOf(entry), 0);
    const costMicros = paid.reduce((sum, entry) => sum + usageCostMicros(entry), 0);
    const row = this.rowFor(subject);
    if (row === undefined) {
      this.dropped += 1;
      return;
    }
    row.calls += calls;
    row.costMicros += costMicros;
  }

  /** Logs every row whose UTC day has ended; a quiet org's day waits for a later call. */
  flushDue(now: number): void {
    const today = utcDayStart(new Date(now)).getTime();
    let flushed = 0;
    for (const [key, row] of this.rows) {
      if (row.dayStart >= today) continue;
      this.log(row, today);
      this.rows.delete(key);
      flushed += 1;
    }
    if (flushed > 0) this.logDropped();
  }

  private rowFor(subject: AskUsageAttribution): SurfaceDay | undefined {
    const surface = 'scope' in subject ? ORG_ONLY_SURFACE : subject.surface;
    const dayStart = utcDayStart(new Date((this.deps.now ?? Date.now)())).getTime();
    const key = [subject.orgId, surface, utcDayKey(new Date(dayStart))].join(KEY_SEPARATOR);
    const existing = this.rows.get(key);
    if (existing !== undefined) return existing;
    if (this.rows.size >= ANSWER_USAGE_MAX_ROWS) return undefined;
    const fresh: SurfaceDay = { orgId: subject.orgId, surface, dayStart, costMicros: 0, calls: 0 };
    this.rows.set(key, fresh);
    return fresh;
  }

  private log(row: SurfaceDay, today: number): void {
    this.deps.logger.info(ANSWER_USAGE_DAILY_EVENT, {
      orgId: row.orgId,
      surface: row.surface,
      costMicros: roundUpTo(row.costMicros, USAGE_LOG_COST_BUCKET_MICROS),
      calls: row.calls,
      daysAgo: Math.round((today - row.dayStart) / MS_PER_DAY),
    });
  }

  private logDropped(): void {
    if (this.dropped === 0) return;
    this.deps.logger.info(ANSWER_USAGE_DROPPED_EVENT, { count: this.dropped });
    this.dropped = 0;
  }
}
