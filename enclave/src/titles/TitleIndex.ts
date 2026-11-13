import { sealedTitleKey, type SealedTitleKind } from '@folklore/contracts';
import type { ResidentIndex } from '../hnsw/IndexResidencyManager.js';

export interface TitleEntry {
  key: string;
  seq: string;
  title: string;
}

interface Held {
  seq: string;
  title: string;
}

const INITIAL_WATERMARK = '0';

export class TitleIndex implements ResidentIndex {
  checkedAt = Number.NEGATIVE_INFINITY;
  reloadedAt = Number.NEGATIVE_INFINITY;
  private readonly held = new Map<string, Held>();
  private readonly read = new Set<string>();
  private readonly noted = new Map<string, string>();
  private highestSeq = INITIAL_WATERMARK;
  private disposed = false;

  private constructor(private readonly onDispose: () => void) {}

  static empty(onDispose: () => void = () => {}): TitleIndex {
    return new TitleIndex(onDispose);
  }

  /** The highest seq read from Postgres; skipped and unseen rows advance it too. */
  get watermark(): string {
    return this.highestSeq;
  }

  /** Rows read from Postgres, skipped and superseded ones included, so it compares with the table's count. */
  get rowCount(): number {
    return this.read.size;
  }

  /** Unseen seqs only move the watermark: the count check, not the next refresh, retries them. */
  apply(
    entries: readonly TitleEntry[],
    skippedSeqs: readonly string[],
    unseenSeqs: readonly string[] = [],
  ): void {
    if (this.disposed) return;
    for (const entry of entries) {
      this.record(entry, true);
      this.advanceWatermark(entry.seq);
    }
    for (const seq of skippedSeqs) {
      if (!this.dropNoted(seq)) this.read.add(seq);
      this.advanceWatermark(seq);
    }
    for (const seq of unseenSeqs) this.advanceWatermark(seq);
  }

  /** Shows a just-committed row at once; it counts as read, and moves the watermark, only when Postgres returns it. */
  noteCommitted(entry: TitleEntry): void {
    if (!this.disposed) this.record(entry, false);
  }

  get(key: string): string | undefined {
    return this.held.get(key)?.title;
  }

  subjects(kind: SealedTitleKind): string[] {
    const prefix = sealedTitleKey(kind, '');
    const subjects: string[] = [];
    for (const key of this.held.keys()) {
      if (key.startsWith(prefix)) subjects.push(key.slice(prefix.length));
    }
    return subjects;
  }

  async flush(): Promise<void> {}

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.held.clear();
    this.read.clear();
    this.noted.clear();
    this.onDispose();
  }

  private record(entry: TitleEntry, confirmed: boolean): void {
    if (this.read.has(entry.seq) || (!confirmed && this.noted.has(entry.seq))) return;
    if (confirmed) {
      this.read.add(entry.seq);
      this.noted.delete(entry.seq);
    } else {
      this.noted.set(entry.seq, entry.key);
    }
    const current = this.held.get(entry.key);
    if (!current || BigInt(entry.seq) > BigInt(current.seq)) {
      this.held.set(entry.key, { seq: entry.seq, title: entry.title });
    }
  }

  // A noted row Postgres calls unusable is left uncounted, so the count check rebuilds the older title.
  private dropNoted(seq: string): boolean {
    const key = this.noted.get(seq);
    if (key === undefined) return false;
    this.noted.delete(seq);
    if (this.held.get(key)?.seq === seq) this.held.delete(key);
    return true;
  }

  private advanceWatermark(seq: string): void {
    if (BigInt(seq) > BigInt(this.highestSeq)) this.highestSeq = seq;
  }
}
