export interface ActivityMonitorDeps {
  quietWindowMs: number;
  now?: () => number;
}

/** Host-level activity signal. */
export class ActivityMonitor {
  private readonly quietWindowMs: number;
  private readonly now: () => number;
  private readonly pins: Array<() => boolean> = [];
  private lastTouchAt?: number;

  constructor(deps: ActivityMonitorDeps) {
    this.quietWindowMs = deps.quietWindowMs;
    this.now = deps.now ?? Date.now;
  }

  touch(): void {
    this.lastTouchAt = this.now();
  }

  // For work that outlives any sane quiet window — an hours-long editing session, a long
  // synthesis job — where "time since the last touch" would report a busy host as quiet.
  addPin(isActive: () => boolean): void {
    this.pins.push(isActive);
  }

  isBusy(): boolean {
    if (this.isPinned()) return true;
    return this.lastTouchAt !== undefined && this.now() - this.lastTouchAt < this.quietWindowMs;
  }

  // Read on the drain loop: a throwing pin must not take that loop down, and an unreadable pin
  // counts as active so the host is never stopped on missing information.
  private isPinned(): boolean {
    for (const isActive of this.pins) {
      try {
        if (isActive()) return true;
      } catch {
        return true;
      }
    }
    return false;
  }
}
