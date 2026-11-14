export type BatchResultRefusal =
  | 'foreign_id'
  | 'malformed'
  | 'model_mismatch'
  | 'usage_invalid'
  | 'oversize_line'
  | 'oversize_body';
export type ManifestRefusal = 'deleted' | 'foreign_name' | 'rolled_back' | 'unreadable';
export type BatchBound = 'rounds' | 'wall' | 'refused';

const OTHER_RESULT_TYPE = 'other';
const LOGGABLE_RESULT_TYPES: ReadonlySet<string> = new Set([
  'invalid_request_error',
  'request_too_large',
  'overloaded_error',
  'api_error',
  'rate_limit_error',
  'authentication_error',
  'permission_error',
  'not_found_error',
  'canceled',
  'expired',
]);

/** The provider's result type when it is one we name, else `other`, so free text never reaches a log. */
export function resultTypeForLog(type: string): string {
  return LOGGABLE_RESULT_TYPES.has(type) ? type : OTHER_RESULT_TYPE;
}

// Keys come from the logging boundary's allow-list; a key outside it costs the whole record.
export const batchLog = {
  submitted: (count: number, round: number) => ['batch_submitted', { count, seq: round }] as const,
  resultErrored: (type: string) =>
    ['batch_result_errored', { error_type: resultTypeForLog(type) }] as const,
  resultRefused: (reason: BatchResultRefusal) => ['batch_result_refused', { reason }] as const,
  manifestRefused: (reason: ManifestRefusal) => ['batch_manifest_refused', { reason }] as const,
  boundsExhausted: (bound: BatchBound) => ['batch_bounds_exhausted', { reason: bound }] as const,
  settleFailed: (orgId: string) => ['batch_settle_failed', { orgId }] as const,
  deletedUnread: (orgId: string) => ['batch_deleted_unread', { orgId }] as const,
  abandonFailed: (orgId: string) => ['batch_abandon_failed', { orgId }] as const,
  finishFailed: (orgId: string) => ['batch_finish_failed', { orgId }] as const,
  collectConflict: (orgId: string) => ['batch_collect_conflict', { orgId }] as const,
  openCountFailed: (orgId: string) => ['batch_open_count_failed', { orgId }] as const,
};
