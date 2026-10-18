import { AsyncLocalStorage } from 'node:async_hooks';
import type { DeadlineBudget } from './PausableDeadline.js';

/** One message's place in the order its batch was received, for the steps that must not interleave. */
export class IndexTurn {
  private released = false;
  private budget: DeadlineBudget | undefined;

  constructor(
    private readonly previous: Promise<void>,
    private readonly onRelease: () => void,
  ) {}

  attachBudget(budget: DeadlineBudget): void {
    this.budget = budget;
  }

  async acquire(): Promise<void> {
    this.budget?.pause();
    try {
      await this.previous;
    } finally {
      this.budget?.resume();
    }
  }

  release(): void {
    if (this.released) return;
    this.released = true;
    this.onRelease();
  }
}

/** Hands out turns in receive order; a turn opens once every earlier one is done, used or not. */
export class IndexTurnQueue {
  private tail: Promise<void> = Promise.resolve();

  next(): IndexTurn {
    const previous = this.tail;
    let release = (): void => {};
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.tail = Promise.all([previous, released]).then(() => undefined);
    return new IndexTurn(previous, release);
  }
}

const storage = new AsyncLocalStorage<IndexTurn>();

export function withIndexTurn<T>(turn: IndexTurn, callback: () => Promise<T>): Promise<T> {
  return storage.run(turn, callback);
}

export function currentIndexTurn(): IndexTurn | undefined {
  return storage.getStore();
}
