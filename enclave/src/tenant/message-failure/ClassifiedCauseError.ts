import { recordWrappedCause, type WrappedCausePrefix } from './message-failure-code.js';

/** A fixed-message failure that keeps the classified reason of the error it replaced, never the error. */
export class ClassifiedCauseError extends Error {
  constructor(message: string, reasonPrefix: WrappedCausePrefix, cause: unknown) {
    super(message);
    this.name = 'ClassifiedCauseError';
    recordWrappedCause(this, reasonPrefix, cause);
  }
}
