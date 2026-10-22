import { LRUCache } from 'lru-cache';

export const LLM_CACHE_RAM_MAX_BYTES = 16 * 1024 * 1024;
export const LLM_CACHE_RAM_IDLE_TTL_MS = 15 * 60_000;
const UTF16_BYTES_PER_CHAR = 2;

export type RamEntry = string | Float32Array;

export interface LlmRamFrontOptions {
  readonly maxBytes?: number;
  readonly idleTtlMs?: number;
}

export class LlmRamFront {
  private readonly lru: LRUCache<string, RamEntry>;

  constructor(options: LlmRamFrontOptions = {}) {
    this.lru = new LRUCache<string, RamEntry>({
      maxSize: options.maxBytes ?? LLM_CACHE_RAM_MAX_BYTES,
      sizeCalculation: LlmRamFront.sizeOf,
      ttl: options.idleTtlMs ?? LLM_CACHE_RAM_IDLE_TTL_MS,
      updateAgeOnGet: true,
      ttlAutopurge: true,
      dispose: LlmRamFront.zero,
    });
  }

  get(key: string): RamEntry | undefined {
    return this.lru.get(key);
  }

  set(key: string, value: RamEntry): void {
    this.lru.set(key, value);
    // An entry larger than the whole budget is refused without a dispose.
    if (!this.lru.has(key)) LlmRamFront.zero(value);
  }

  delete(key: string): boolean {
    return this.lru.delete(key);
  }

  clear(): void {
    this.lru.clear();
  }

  private static sizeOf(value: RamEntry): number {
    const bytes =
      typeof value === 'string' ? value.length * UTF16_BYTES_PER_CHAR : value.byteLength;
    return Math.max(1, bytes);
  }

  // Strings are immutable in JS and cannot be wiped; only the typed array is.
  private static zero(value: RamEntry): void {
    if (typeof value !== 'string') value.fill(0);
  }
}
