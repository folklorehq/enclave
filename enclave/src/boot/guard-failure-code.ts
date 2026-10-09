import { contentFreeErrorType, isFailureCodeSlug } from '@folklore/core';

/** A content-free code for a failure: its guard slug, else the fallback qualified by its error class. */
export function guardFailureCode(error: unknown, fallback: string): string {
  // A message is relayed only when it is already a guard slug; anything else may echo a value.
  if (error instanceof Error && isFailureCodeSlug(error.message)) return error.message;
  return errorClassCode(error, fallback);
}

/** The fallback qualified by the error's class only; the message is never read. */
export function errorClassCode(error: unknown, fallback: string): string {
  if (!(error instanceof Error)) return fallback;
  const errorType = contentFreeErrorType(error);
  const named = errorType === null ? null : `${fallback}_${errorType}`;
  return isFailureCodeSlug(named) ? named : fallback;
}
