const REFRESH_INTERVAL_MS = 60 * 60_000;
const HELD_AFTER_INVALIDATION_MS = 60_000;

export type KeyInvalidation = 'rejected' | 'mismatch';

export interface ProviderKeyHolderDeps {
  readonly load: () => Promise<Buffer>;
  readonly heldError: (reason: KeyInvalidation) => Error;
  readonly now?: () => number;
}

interface LoadedKey {
  readonly bytes: Buffer;
  readonly loadedAt: number;
}

interface Hold {
  readonly reason: KeyInvalidation;
  readonly at: number;
}

/** Keeps one provider key for an hour, shares one in-flight load, and refuses for a minute after an invalidation. */
export class ProviderKeyHolder {
  private loaded: LoadedKey | undefined;
  private inflight: Promise<LoadedKey> | undefined;
  private hold: Hold | undefined;
  private readonly now: () => number;

  constructor(private readonly deps: ProviderKeyHolderDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  async key(): Promise<string> {
    this.assertNotHeld();
    const current = this.loaded;
    if (current !== undefined && this.now() - current.loadedAt < REFRESH_INTERVAL_MS) {
      return current.bytes.toString('utf8');
    }
    const loaded = await (this.inflight ??= this.load().finally(() => {
      this.inflight = undefined;
    }));
    return loaded.bytes.toString('utf8');
  }

  invalidate(reason: KeyInvalidation): void {
    this.loaded?.bytes.fill(0);
    this.loaded = undefined;
    this.hold ??= { reason, at: this.now() };
  }

  private assertNotHeld(): void {
    if (this.hold === undefined) return;
    if (this.now() - this.hold.at < HELD_AFTER_INVALIDATION_MS) {
      throw this.deps.heldError(this.hold.reason);
    }
    this.hold = undefined;
  }

  private async load(): Promise<LoadedKey> {
    const bytes = await this.deps.load();
    this.loaded?.bytes.fill(0);
    this.loaded = { bytes, loadedAt: this.now() };
    return this.loaded;
  }
}
