export const PINNED_UPSTREAM_TIMEOUT = 'upstream_timeout';

const TLS_VERIFY_CODE =
  /^(?:CERT_|UNABLE_TO_|ERR_TLS_CERT_|DEPTH_ZERO_SELF_SIGNED_CERT$|SELF_SIGNED_CERT_IN_CHAIN$)/;
const TIMEOUT_CODE = /^UND_ERR_(?:CONNECT|HEADERS|BODY)_TIMEOUT$/;
const NATIVE_TIMEOUT_NAME = 'TimeoutError';
const MAX_CAUSE_DEPTH = 6;

export interface PinnedFailureNames<T extends string> {
  readonly tlsUntrusted: T;
  readonly timeout: T;
  readonly own: ReadonlySet<T>;
}

/** Names a failure from error codes and our own slugs only, so no upstream text can reach the result. */
export function pinnedTransportFailureOf<T extends string>(
  error: unknown,
  names: PinnedFailureNames<T>,
): T | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
    const named = nameOf(current, names);
    if (named !== undefined) return named;
    current = current.cause;
  }
  return undefined;
}

function nameOf<T extends string>(error: Error, names: PinnedFailureNames<T>): T | undefined {
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && TLS_VERIFY_CODE.test(code)) return names.tlsUntrusted;
  if (typeof code === 'string' && TIMEOUT_CODE.test(code)) return names.timeout;
  if (error.name === NATIVE_TIMEOUT_NAME) return names.timeout;
  return names.own.has(error.message as T) ? (error.message as T) : undefined;
}
