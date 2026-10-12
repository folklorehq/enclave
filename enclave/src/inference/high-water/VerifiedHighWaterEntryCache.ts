import type { HighWaterLogEntryV1 } from '@folklore/contracts';

export interface VerifiedHighWaterEntry {
  readonly entry: HighWaterLogEntryV1;
  readonly objectBytes: number;
}

interface CachedEntry extends VerifiedHighWaterEntry {
  readonly cost: number;
}

/** Settled, verified high-water entries per tenant+deployment prefix, under a hard cost ceiling. */
export class VerifiedHighWaterEntryCache {
  readonly #prefixes = new Map<string, Map<string, CachedEntry>>();
  #cost = 0;

  constructor(
    private readonly maxCost: number,
    private readonly maxPrefixes: number,
  ) {
    if (!Number.isSafeInteger(maxCost) || maxCost < 0 || !Number.isSafeInteger(maxPrefixes)) {
      throw new Error('high_water_cache_config_invalid');
    }
  }

  get cost(): number {
    return this.#cost;
  }

  // A dropped or replaced version is forgotten here, so only versions the current listing names are reused.
  retainListed(prefix: string, listed: ReadonlySet<string>): void {
    const previous = this.#prefixes.get(prefix);
    const retained = new Map<string, CachedEntry>();
    for (const [id, cached] of previous ?? []) {
      if (listed.has(id)) retained.set(id, cached);
      else this.#cost -= cached.cost;
    }
    this.#prefixes.delete(prefix);
    this.#prefixes.set(prefix, retained);
    this.evictOthersUntil(prefix, 0);
  }

  get(prefix: string, id: string): VerifiedHighWaterEntry | undefined {
    return this.#prefixes.get(prefix)?.get(id);
  }

  admit(prefix: string, id: string, verified: VerifiedHighWaterEntry): void {
    if (this.#prefixes.get(prefix)?.has(id)) return;
    const cost = this.costOf(verified.entry);
    if (cost > this.maxCost) return;
    let entries = this.#prefixes.get(prefix);
    if (!entries) {
      entries = new Map();
      this.#prefixes.set(prefix, entries);
    }
    if (!this.evictOthersUntil(prefix, cost)) return;
    entries.set(id, { ...verified, cost });
    this.#cost += cost;
  }

  private evictOthersUntil(keep: string, incoming: number): boolean {
    for (const [prefix, entries] of this.#prefixes) {
      if (this.fits(incoming)) return true;
      if (prefix === keep) continue;
      for (const cached of entries.values()) this.#cost -= cached.cost;
      this.#prefixes.delete(prefix);
    }
    return this.fits(incoming);
  }

  private fits(incoming: number): boolean {
    return this.#prefixes.size <= this.maxPrefixes && this.#cost + incoming <= this.maxCost;
  }

  // Approximates the decoded entry's resident size by its JSON form; digests and keys dominate either way.
  private costOf(entry: HighWaterLogEntryV1): number {
    return Buffer.byteLength(JSON.stringify(entry));
  }
}
