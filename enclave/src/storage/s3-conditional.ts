const CONDITIONAL_CONFLICT_STATUSES: ReadonlySet<number> = new Set([409, 412]);
const CONDITIONAL_CONFLICT_NAMES: ReadonlySet<string> = new Set([
  'PreconditionFailed',
  'ConditionalRequestConflict',
]);

export function isS3ConditionalConflict(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  const status = candidate.$metadata?.httpStatusCode;
  return (
    (typeof candidate.name === 'string' && CONDITIONAL_CONFLICT_NAMES.has(candidate.name)) ||
    (typeof status === 'number' && CONDITIONAL_CONFLICT_STATUSES.has(status))
  );
}
