const MAX_CAUSE_DEPTH = 4;
const FIRST_SERVER_ERROR_STATUS = 500;
const TRANSIENT_SERVICE_ERRORS: ReadonlySet<string> = new Set([
  'ThrottlingException',
  'TooManyRequestsException',
  'RequestLimitExceeded',
  'KMSInternalException',
  'DependencyTimeoutException',
  'ServiceUnavailable',
  'InternalFailure',
]);

interface ServiceError {
  name?: unknown;
  $metadata: { httpStatusCode?: unknown };
}

// Only a transient service fault says nothing about the blob; a refused or forged key is damage and must alarm.
export function isServiceFault(err: unknown, depth = 0): boolean {
  if (typeof err !== 'object' || err === null || depth > MAX_CAUSE_DEPTH) return false;
  if (!('$metadata' in err)) return isServiceFault((err as { cause?: unknown }).cause, depth + 1);
  const { name, $metadata: metadata } = err as ServiceError;
  const status = metadata?.httpStatusCode;
  return (
    (typeof status === 'number' && status >= FIRST_SERVER_ERROR_STATUS) ||
    (typeof name === 'string' && TRANSIENT_SERVICE_ERRORS.has(name))
  );
}
