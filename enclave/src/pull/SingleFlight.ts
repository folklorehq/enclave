export class SingleFlight<T> {
  private readonly inflight = new Map<string, Promise<T>>();

  run(key: string, task: () => Promise<T>): Promise<T> {
    const running = this.inflight.get(key);
    if (running) return running;
    const started = task().finally(() => this.inflight.delete(key));
    this.inflight.set(key, started);
    return started;
  }
}
