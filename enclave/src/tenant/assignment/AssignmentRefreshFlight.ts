export type IsCurrentRefresh = () => boolean;
export type AssignmentRefresh = (isCurrent: IsCurrentRefresh) => Promise<void>;

/** Runs one assignment refresh at a time; a stalled one frees the slot but cannot act once superseded. */
export class AssignmentRefreshFlight {
  private inFlight: Promise<void> | undefined;
  private epoch = 0;

  constructor(
    private readonly refresh: AssignmentRefresh,
    private readonly stallMs: number,
    private readonly onStall: () => void,
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
    }
  }

  private release(flight: Promise<void>): void {
    if (this.inFlight === flight) this.inFlight = undefined;
  }
}
