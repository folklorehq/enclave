export const CHUNK_QUEUE_MAX = 256;

export type ChunkQueueFailure =
  | 'chunk_queue_closed'
  | 'chunk_queue_full'
  | 'chunk_queue_no_pending_read';

export class ChunkQueueError extends Error {
  constructor(readonly code: ChunkQueueFailure) {
    super(code);
    this.name = 'ChunkQueueError';
  }
}

interface PendingRead<T> {
  readonly resolve: (result: IteratorResult<T>) => void;
  readonly reject: (error: unknown) => void;
}

/** A single-consumer queue a producer fills; an early consumer return signals the producer to stop. */
export class ChunkQueue<T> implements AsyncIterable<T> {
  private readonly items: T[] = [];
  private pending: PendingRead<T> | undefined;
  private ended = false;
  private failure: { readonly error: unknown } | undefined;
  private consumerReturned = false;

  constructor(private readonly onConsumerReturn: () => void) {}

  push(item: T): void {
    if (this.ended || this.failure !== undefined) throw new ChunkQueueError('chunk_queue_closed');
    if (this.consumerReturned) return;
    if (this.pending !== undefined) {
      this.settle().resolve({ value: item, done: false });
      return;
    }
    if (this.items.length >= CHUNK_QUEUE_MAX) throw new ChunkQueueError('chunk_queue_full');
    this.items.push(item);
  }

  end(): void {
    if (this.ended || this.failure !== undefined) return;
    this.ended = true;
    if (this.pending !== undefined) this.settle().resolve({ value: undefined, done: true });
  }

  fail(error: unknown): void {
    if (this.ended || this.failure !== undefined) return;
    this.failure = { error };
    if (this.pending !== undefined) this.settle().reject(error);
  }

  [Symbol.asyncIterator](): AsyncIterator<T> {
    return {
      next: () => this.next(),
      return: () => this.returnEarly(),
    };
  }

  private next(): Promise<IteratorResult<T>> {
    if (this.consumerReturned) return Promise.resolve({ value: undefined, done: true });
    if (this.items.length > 0) {
      return Promise.resolve({ value: this.items.shift() as T, done: false });
    }
    if (this.failure !== undefined) return Promise.reject(this.failure.error);
    if (this.ended) return Promise.resolve({ value: undefined, done: true });
    return new Promise((resolve, reject) => {
      this.pending = { resolve, reject };
    });
  }

  private returnEarly(): Promise<IteratorResult<T>> {
    if (!this.consumerReturned) {
      this.consumerReturned = true;
      this.items.length = 0;
      if (this.pending !== undefined) this.settle().resolve({ value: undefined, done: true });
      this.onConsumerReturn();
    }
    return Promise.resolve({ value: undefined, done: true });
  }

  private settle(): PendingRead<T> {
    const read = this.pending;
    if (read === undefined) throw new ChunkQueueError('chunk_queue_no_pending_read');
    this.pending = undefined;
    return read;
  }
}
