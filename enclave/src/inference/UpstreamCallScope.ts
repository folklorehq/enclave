import { AsyncLocalStorage } from 'node:async_hooks';
import type { DeadlineBudget } from '../ingest/PausableDeadline.js';

export const UNSCOPED_MESSAGE = 0;

export interface UpstreamCallContext {
  /** An in-enclave counter naming one message's calls for rotation; it never leaves the enclave. */
  readonly message: number;
  readonly signal?: AbortSignal;
  /** When the message's timer fires, fixed at the start; absent when the timer can pause, as a queue job's does. */
  readonly deadlineAtMs?: number;
  /** A queue job's calls wait in the host gate; an interactive answer's never do. */
  readonly background?: boolean;
  /** The message's timer, paused while one of its calls queues in the host gate. */
  readonly waitBudget?: DeadlineBudget;
}

let messageSequence = UNSCOPED_MESSAGE;

export function nextUpstreamMessage(): number {
  return ++messageSequence;
}

export class UpstreamCallScope {
  private readonly storage = new AsyncLocalStorage<UpstreamCallContext>();

  run<T>(context: UpstreamCallContext, fn: () => Promise<T>): Promise<T> {
    return this.storage.run(context, fn);
  }

  current(): UpstreamCallContext | undefined {
    return this.storage.getStore();
  }
}

export const upstreamCallScope = new UpstreamCallScope();
