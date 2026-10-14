import { ServiceUnavailableError } from '@folklore/errors';
import { recordWrappedCause, type WrappedCausePrefix } from './message-failure-code.js';

/** An unavailable refusal that keeps the classified reason of the failure it replaced, never the failure. */
export class ClassifiedUnavailableError extends ServiceUnavailableError {
  constructor(message: string, code: string, reasonPrefix: WrappedCausePrefix, cause: unknown) {
    super(message, code);
    recordWrappedCause(this, reasonPrefix, cause);
  }
}
