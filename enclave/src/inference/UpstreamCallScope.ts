import { AsyncLocalStorage } from 'node:async_hooks';

export const UNSCOPED_MESSAGE = 0;

export interface UpstreamCallContext {
  /** An in-enclave counter naming one message's calls for rotation; it never leaves the enclave. */
  readonly message: number;
  readonly signal?: AbortSignal;
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
