import pLimit, { type LimitFunction } from 'p-limit';

const CONNECTOR_SLOTS_PER_ORG_KIND = 8;
const KEY_SEPARATOR = '\u0000';

interface Slot {
  readonly limit: LimitFunction;
  waiting: number;
}

export class ConnectorConcurrency {
  private readonly slots = new Map<string, Slot>();

  async run<T>(orgId: string, kind: string, task: () => Promise<T>): Promise<T> {
    const key = `${orgId}${KEY_SEPARATOR}${kind}`;
    const slot = this.slots.get(key) ?? this.open(key);
    slot.waiting += 1;
    try {
      return await slot.limit(task);
    } finally {
      slot.waiting -= 1;
      if (slot.waiting === 0 && this.slots.get(key) === slot) this.slots.delete(key);
    }
  }

  size(): number {
    return this.slots.size;
  }

  private open(key: string): Slot {
    const slot: Slot = { limit: pLimit(CONNECTOR_SLOTS_PER_ORG_KIND), waiting: 0 };
    this.slots.set(key, slot);
    return slot;
  }
}
