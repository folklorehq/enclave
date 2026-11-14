import { INFERENCE_PURPOSES } from '@folklore/contracts';
import { claudeMaxTokens } from './claude-purpose-limits.js';
import { CHARS_PER_TOKEN_FLOOR } from '../token-floor.js';

const HOUR_MS = 60 * 60_000;

export const BATCH_MAX_ROUNDS = 18;
export const BATCH_MAX_WALL_MS = 48 * HOUR_MS;
export const BATCH_MAX_REQUESTS_PER_SUBMIT = 1_000;
export const BATCH_SETTLES_PER_TOUCH = 4;
export const BATCH_MANIFEST_WRITE_ATTEMPTS = 3;

const UTF8_MAX_BYTES_PER_CHAR = 4;
const HIGHEST_MAX_TOKENS = Math.max(
  ...INFERENCE_PURPOSES.map((purpose) => claudeMaxTokens(purpose, 'high')),
);

export const BATCH_RESULT_LINE_ENVELOPE_BYTES = 64 * 1024;
// The highest max_tokens any purpose is sent with, at the synchronous meter's 3 chars a token and 4 UTF-8 bytes a char.
export const BATCH_RESULT_LINE_MAX_BYTES =
  HIGHEST_MAX_TOKENS * CHARS_PER_TOKEN_FLOOR * UTF8_MAX_BYTES_PER_CHAR +
  BATCH_RESULT_LINE_ENVELOPE_BYTES;
// One line is held as bytes, as a string, as a parsed value and as the sealed text, so its peak is a small multiple of its size.
export const BATCH_RESULT_LINE_MEMORY_FACTOR = 8;
export const BATCH_RESULTS_IDLE_TIMEOUT_MS = 60_000;
export const BATCH_RESULTS_BASE_BUDGET_MS = 60_000;
export const BATCH_RESULT_REQUEST_BUDGET_MS = 1_000;
export const BATCH_CANCEL_PASS_BUDGET_MS = 120_000;
export const BATCH_ERASE_READ_CUT_LIMIT = 2;
// How long the collector trusts its index of an org's unclosed manifests before it lists them again.
export const BATCH_INDEX_RELIST_MS = HOUR_MS;

export function batchResultsMaxBytes(requests: number): number {
  return requests * BATCH_RESULT_LINE_MAX_BYTES;
}

// The base plus a second for each request the batch was submitted with, which covers reading and sealing that request's line.
export function batchResultsBudgetMs(requests: number): number {
  return BATCH_RESULTS_BASE_BUDGET_MS + requests * BATCH_RESULT_REQUEST_BUDGET_MS;
}
