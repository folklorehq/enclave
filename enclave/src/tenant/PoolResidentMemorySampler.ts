import { poolResidentMemoryKey } from '@folklore/contracts';
import type { Cache } from '@folklore/core';
import { poolResidentMemorySchema, type PoolResidentMemory } from '@folklore/control-plane';

export interface ResidentMemoryReaders {
  /** Throws when unreadable. */
  readonly meminfo: () => string;
  readonly rssBytes: () => number;
  readonly tenantCount: () => number;
  readonly now: () => number;
}

export const POOL_RESIDENT_MEMORY_TTL_SECONDS = 300;

const MEM_TOTAL_LINE = /^MemTotal:\s+(\d+) kB$/m;
const MEM_AVAILABLE_LINE = /^MemAvailable:\s+(\d+) kB$/m;
const KIB_PER_MIB = 1024;
const BYTES_PER_MIB = 1024 * 1024;
const MS_PER_SECOND = 1000;
const REFRESH_AFTER_MS = (POOL_RESIDENT_MEMORY_TTL_SECONDS * MS_PER_SECOND) / 2;

/** Writes one enclave-wide memory reading for the host agent to relay; it names no tenant. */
export class PoolResidentMemorySampler {
  private last: PoolResidentMemory | undefined;
  private lastWrittenAt: number | undefined;
  private peakCount: number | undefined;
  private peak = 0;

  constructor(
    private readonly cache: Pick<Cache, 'set'>,
    private readonly deploymentId: string,
    private readonly readers: ResidentMemoryReaders,
  ) {}

  async sample(): Promise<void> {
    const reading = this.read();
    if (!reading || !this.shouldWrite(reading)) return;
    if (!(await this.write(reading))) return;
    this.last = reading;
    this.lastWrittenAt = this.readers.now();
  }

  private async write(reading: PoolResidentMemory): Promise<boolean> {
    try {
      await this.cache.set(
        poolResidentMemoryKey(this.deploymentId),
        reading,
        POOL_RESIDENT_MEMORY_TTL_SECONDS,
      );
      return true;
    } catch {
      return false;
    }
  }

  private read(): PoolResidentMemory | undefined {
    try {
      const meminfo = this.readers.meminfo();
      const totalKib = this.kib(MEM_TOTAL_LINE, meminfo);
      const availableKib = this.kib(MEM_AVAILABLE_LINE, meminfo);
      if (totalKib === undefined || availableKib === undefined) return undefined;
      const used = Math.ceil((totalKib - availableKib) / KIB_PER_MIB);
      const tenantCount = this.readers.tenantCount();
      const parsed = poolResidentMemorySchema.safeParse({
        schema: 'PoolResidentMemoryV1',
        enclave_total_mib: Math.floor(totalKib / KIB_PER_MIB),
        enclave_used_mib: used,
        peak_used_mib: this.nextPeak(used, tenantCount),
        process_rss_mib: Math.ceil(this.readers.rssBytes() / BYTES_PER_MIB),
        tenant_count: tenantCount,
      });
      return parsed.success ? parsed.data : undefined;
    } catch {
      return undefined;
    }
  }

  private kib(line: RegExp, meminfo: string): number | undefined {
    const value = line.exec(meminfo)?.[1];
    return value === undefined ? undefined : Number(value);
  }

  // The peak is per tenant count, so a join or departure starts a fresh state.
  private nextPeak(used: number, tenantCount: number): number {
    this.peak = this.peakCount === tenantCount ? Math.max(this.peak, used) : used;
    this.peakCount = tenantCount;
    return this.peak;
  }

  private shouldWrite(reading: PoolResidentMemory): boolean {
    if (!this.last || this.lastWrittenAt === undefined) return true;
    const stale = this.readers.now() - this.lastWrittenAt >= REFRESH_AFTER_MS;
    return stale || JSON.stringify(reading) !== JSON.stringify(this.last);
  }
}
