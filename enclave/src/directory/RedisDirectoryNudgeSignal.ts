import type { RedisCache } from '@folklore/cache';
import { poolDirectoryNudgesKey } from '@folklore/contracts';
import { z } from 'zod';
import type { TenantExpediteSignal } from '../tenant/TenantPeriodicRunner.js';

const MAX_LIST_CHARS = 1_048_576;
const nudgeListSchema = z.record(z.string().uuid(), z.number().int().positive().safe());

/** Reads the host's list of tenants whose directory changed; only its changes matter, never its content. */
export class RedisDirectoryNudgeSignal implements TenantExpediteSignal {
  constructor(
    private readonly redis: Pick<RedisCache['redis'], 'get'>,
    private readonly poolId: string,
  ) {}

  async read(): Promise<ReadonlyMap<string, string>> {
    const raw = await this.redis.get(poolDirectoryNudgesKey(this.poolId));
    if (raw === null || raw.length > MAX_LIST_CHARS) return new Map();
    const parsed = nudgeListSchema.safeParse(this.parseJson(raw));
    if (!parsed.success) return new Map();
    return new Map(Object.entries(parsed.data).map(([orgId, seq]) => [orgId, String(seq)]));
  }

  private parseJson(raw: string): unknown {
    try {
      return JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
}
