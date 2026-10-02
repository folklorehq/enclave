const INGEST_FUNCTION_PREFIX = 'folklore-';
const INGEST_FUNCTION_SUFFIX = '-ingest';

export function ingestFunctionName(orgId: string): string {
  return `${INGEST_FUNCTION_PREFIX}${orgId}${INGEST_FUNCTION_SUFFIX}`;
}
