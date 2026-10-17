import { AsyncLocalStorage } from 'node:async_hooks';
import type { ClaudeArmId, ClaudeInferencePurpose } from '@folklore/contracts';

export const DEFAULT_ARM = 'D' satisfies ClaudeArmId;

export interface CachedSystemPrefix {
  readonly salt: string;
  readonly rules: string;
  readonly facts: string;
  readonly digest: string;
}

export interface InferencePurposeContext {
  readonly purpose: ClaudeInferencePurpose;
  readonly arm: ClaudeArmId;
  readonly cachedSystemPrefix?: CachedSystemPrefix;
}

class InferencePurposeStore {
  private readonly storage = new AsyncLocalStorage<InferencePurposeContext>();

  run<T>(context: InferencePurposeContext, fn: () => Promise<T>): Promise<T> {
    return this.storage.run(context, fn);
  }

  current(): InferencePurposeContext | undefined {
    return this.storage.getStore();
  }
}

export const inferencePurposeScope = new InferencePurposeStore();

export function withPurpose<T>(
  purpose: ClaudeInferencePurpose,
  fn: () => Promise<T>,
  prefix?: CachedSystemPrefix,
): Promise<T> {
  const arm = inferencePurposeScope.current()?.arm ?? DEFAULT_ARM;
  return inferencePurposeScope.run(
    { purpose, arm, ...(prefix === undefined ? {} : { cachedSystemPrefix: prefix }) },
    fn,
  );
}
