export class KeyedSemaphore {
  private readonly held = new Map<string, number>();
  private readonly waiters = new Map<string, Array<() => void>>();

  constructor(private readonly limit: number) {}

  async run<T>(key: string, task: () => Promise<T>): Promise<T> {
    await this.acquire(key);
    try {
      return await task();
    } finally {
      this.release(key);
    }
  }

  private acquire(key: string): Promise<void> {
    const held = this.held.get(key) ?? 0;
    if (held < this.limit) {
      this.held.set(key, held + 1);
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      const queue = this.waiters.get(key) ?? [];
      queue.push(resolve);
      this.waiters.set(key, queue);
    });
  }

  private release(key: string): void {
    const next = this.waiters.get(key)?.shift();
    if (next) {
      next();
      return;
    }
    const held = (this.held.get(key) ?? 1) - 1;
    if (held <= 0) this.held.delete(key);
    else this.held.set(key, held);
    if (this.waiters.get(key)?.length === 0) this.waiters.delete(key);
  }
}
