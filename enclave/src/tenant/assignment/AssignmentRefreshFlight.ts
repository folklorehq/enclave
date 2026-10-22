export type IsCurrentRefresh = () => boolean;
export type AssignmentRefresh = (isCurrent: IsCurrentRefresh) => Promise<void>;

// Coalesces a burst of wake signals into at most one extra refresh per gap.
export const ASSIGNMENT_WAKE_MIN_GAP_MS = 1_000;

/** Runs one assignment refresh at a time; a stalled one frees the slot but cannot act once superseded. */
export class AssignmentRefreshFlight {
  private inFlight: Promise<void> | undefined;
  private epoch = 0;
  private again = false;
  private lastWakeStartAt: number | undefined;
  private trailing: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly refresh: AssignmentRefresh,
    private readonly stallMs: number,
    private readonly onStall: () => void,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async run(): Promise<void> {
    if (this.inFlight) return;
    const epoch = ++this.epoch;
    const current = this.refresh(() => epoch === this.epoch);
    this.inFlight = current;
    const stallTimer = setTimeout(() => {
      this.onStall();
      this.release(current);
    }, this.stallMs);
    try {
      await current;
    } finally {
      clearTimeout(stallTimer);
      this.release(current);
      this.startAgain();
    }
  }

  wake(): void {
    if (this.inFlight) {
      this.again = true;
      return;
    }
    if (this.withinGap()) {
      this.again = true;
      this.armTrailing();
      return;
    }
    this.startForWake();
  }

  private startAgain(): void {
    if (!this.again || this.inFlight) return;
    if (this.withinGap()) {
      this.armTrailing();
      return;
    }
    this.again = false;
    this.startForWake();
  }

  private startForWake(): void {
    this.lastWakeStartAt = this.now();
    // The refresh logs its own failures; a wake must never crash the process.
    void this.run().catch(() => undefined);
  }

  private withinGap(): boolean {
    return (
      this.lastWakeStartAt !== undefined &&
      this.now() - this.lastWakeStartAt < ASSIGNMENT_WAKE_MIN_GAP_MS
    );
  }

  private armTrailing(): void {
    if (this.trailing || this.lastWakeStartAt === undefined) return;
    const remaining = this.lastWakeStartAt + ASSIGNMENT_WAKE_MIN_GAP_MS - this.now();
    this.trailing = setTimeout(
      () => {
        this.trailing = undefined;
        if (!this.again) return;
        this.again = false;
        if (this.inFlight) {
          this.again = true;
          return;
        }
        this.startForWake();
      },
      Math.max(0, remaining),
    );
  }

  private release(flight: Promise<void>): void {
    if (this.inFlight === flight) this.inFlight = undefined;
  }
}
