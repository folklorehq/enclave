const DEFAULT_WINDOW_MS = 60 * 1000;
const DEFAULT_LIMIT = Number(process.env['PREVIEW_RATE_LIMIT_RPM'] ?? 60);
const MAX_TRACKED_KEYS = 10_000;

// Fixed-window counter per key, mirroring ingest-proxy/rate-limiter.ts. In-process (not
// DynamoDB) because the egress proxy is one long-running parent-EC2 server, not a Lambda.
export class RateLimiter {
  private readonly counts = new Map<string, { window: number; count: number }>();

  constructor(
    private readonly limit = DEFAULT_LIMIT,
    private readonly windowMs = DEFAULT_WINDOW_MS,
  ) {}

  check(key: string): boolean {
    const window = Math.floor(Date.now() / this.windowMs);
    const entry = this.counts.get(key);
    if (!entry || entry.window !== window) {
      this.evictIfLarge(window);
      this.counts.set(key, { window, count: 1 });
      return true;
    }
    entry.count += 1;
    return entry.count <= this.limit;
  }

  private evictIfLarge(currentWindow: number): void {
    if (this.counts.size < MAX_TRACKED_KEYS) return;
    for (const [key, entry] of this.counts) {
      if (entry.window !== currentWindow) this.counts.delete(key);
    }
  }
}
