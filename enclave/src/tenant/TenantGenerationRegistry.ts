export interface TenantGenerationEntry<TContext, TSnapshot> {
  readonly context: TContext;
  readonly snapshot: TSnapshot;
}

export interface TenantGenerationPointer<TContext, TSnapshot> {
  readonly generation: number;
  readonly digest?: string;
  readonly entries: ReadonlyMap<string, TenantGenerationEntry<TContext, TSnapshot>>;
}

class ReadonlyStateMap<T> implements ReadonlyMap<string, T> {
  private readonly map: Map<string, T>;

  constructor(entries: Iterable<readonly [string, T]>) {
    this.map = new Map(entries);
  }

  get size(): number {
    return this.map.size;
  }

  get(key: string): T | undefined {
    return this.map.get(key);
  }

  has(key: string): boolean {
    return this.map.has(key);
  }

  entries(): MapIterator<[string, T]> {
    return this.map.entries();
  }

  keys(): MapIterator<string> {
    return this.map.keys();
  }

  values(): MapIterator<T> {
    return this.map.values();
  }

  forEach(callbackfn: (value: T, key: string, map: ReadonlyMap<string, T>) => void): void {
    this.map.forEach((value, key) => callbackfn(value, key, this));
  }

  [Symbol.iterator](): MapIterator<[string, T]> {
    return this.entries();
  }
}

export class TenantGenerationRegistry<TContext = unknown, TSnapshot = unknown> {
  private current: TenantGenerationPointer<TContext, TSnapshot> = Object.freeze({
    generation: 0,
    entries: new ReadonlyStateMap<TenantGenerationEntry<TContext, TSnapshot>>([]),
  });

  generation(): number {
    return this.current.generation;
  }

  get(tenantId: string): TenantGenerationEntry<TContext, TSnapshot> | undefined {
    return this.current.entries.get(tenantId);
  }

  entries(): ReadonlyMap<string, TenantGenerationEntry<TContext, TSnapshot>> {
    return this.current.entries;
  }

  read(): TenantGenerationPointer<TContext, TSnapshot> {
    return this.current;
  }

  replaceGeneration(
    expectedGeneration: number,
    nextState: ReadonlyMap<string, TenantGenerationEntry<TContext, TSnapshot>>,
    nextGeneration = expectedGeneration + 1,
    digest?: string,
  ): TenantGenerationPointer<TContext, TSnapshot> {
    if (this.current.generation !== expectedGeneration) {
      throw new Error('tenant_generation_compare_and_set_failed');
    }
    if (!Number.isSafeInteger(nextGeneration) || nextGeneration !== expectedGeneration + 1) {
      throw new Error('tenant_generation_invalid');
    }
    const entries = [...nextState].map(
      ([tenantId, entry]) =>
        [
          tenantId,
          Object.freeze({
            context: entry.context,
            snapshot: entry.snapshot,
          }),
        ] as const,
    );
    this.current = Object.freeze({
      generation: nextGeneration,
      ...(digest === undefined ? {} : { digest }),
      entries: new ReadonlyStateMap(entries),
    });
    return this.current;
  }
}
