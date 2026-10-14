import { ServiceUnavailableError } from '@folklore/errors';

declare const FAILURE_REASON: unique symbol;

/** A closed-set failure reason; only the message-failure classifier mints one. */
export type FailureReason = string & { readonly [FAILURE_REASON]: true };

/** An unavailable refusal that keeps the classified reason of the failure it replaced, never the failure. */
export class ClassifiedUnavailableError extends ServiceUnavailableError {
  readonly reasonPrefix: string;
  readonly causeReason: FailureReason | undefined;

  constructor(
    message: string,
    code: string,
    reasonPrefix: string,
    causeReason: FailureReason | undefined,
  ) {
    super(message, code);
    this.reasonPrefix = reasonPrefix;
    this.causeReason = causeReason;
  }
}
