export interface DeadlineBudget {
  pause(): void;
  resume(): void;
}

/** A timeout whose clock stops while any caller holds a pause, so time queued behind others is not spent budget. */
export class PausableDeadline implements DeadlineBudget {
  private remainingMs: number;
  private armedAt = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private isStarted = false;
  private pauseDepth = 0;
  private isDone = false;

  constructor(
    budgetMs: number,
    private readonly onExpire: () => void,
  ) {
    this.remainingMs = budgetMs;
  }

  start(): void {
    if (this.isDone || this.isStarted) return;
    this.isStarted = true;
    if (this.pauseDepth === 0) this.arm();
  }

  pause(): void {
    if (this.isDone) return;
    this.pauseDepth += 1;
    if (this.pauseDepth > 1 || !this.isStarted) return;
    this.disarm();
    this.remainingMs = Math.max(0, this.remainingMs - (Date.now() - this.armedAt));
  }

  resume(): void {
    if (this.isDone || this.pauseDepth === 0) return;
    this.pauseDepth -= 1;
    if (this.pauseDepth === 0 && this.isStarted) this.arm();
  }

  clear(): void {
    this.isDone = true;
    this.disarm();
  }

  private arm(): void {
    this.disarm();
    this.armedAt = Date.now();
    this.timer = setTimeout(() => {
      if (this.isDone) return;
      this.isDone = true;
      this.onExpire();
    }, this.remainingMs);
  }

  private disarm(): void {
    clearTimeout(this.timer);
    this.timer = undefined;
  }
}
