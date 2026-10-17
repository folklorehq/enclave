import { AsyncLocalStorage } from 'node:async_hooks';

export interface AttestationTurnContext {
  /** Pass-through calls and policy floor reads: even their checkpoints take priority turns. */
  readonly priority?: boolean;
  /** Aborted once the owning read settled: every still-queued turn of it is skipped. */
  readonly abandonRead?: AbortSignal;
  /** Aborted when one refresh attempt timed out: only that attempt's samples are skipped. */
  readonly abandonAttempt?: AbortSignal;
}

export class AttestationTurnScope {
  private readonly storage = new AsyncLocalStorage<AttestationTurnContext>();

  run<T>(patch: AttestationTurnContext, fn: () => Promise<T>): Promise<T> {
    return this.storage.run({ ...this.current(), ...patch }, fn);
  }

  current(): AttestationTurnContext {
    return this.storage.getStore() ?? {};
  }
}

export const attestationTurnScope = new AttestationTurnScope();
