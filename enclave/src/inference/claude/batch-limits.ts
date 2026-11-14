import { INFERENCE_PURPOSES } from '@folklore/contracts';
import { claudeMaxTokens } from './claude-purpose-limits.js';
import { CHARS_PER_TOKEN_FLOOR } from '../token-floor.js';

const HOUR_MS = 60 * 60_000;

export const BATCH_MAX_ROUNDS = 18;
export const BATCH_MAX_WALL_MS = 48 * HOUR_MS;
export const BATCH_MAX_REQUESTS_PER_SUBMIT = 1_000;
export const BATCH_SETTLES_PER_TOUCH = 4;

const UTF8_MAX_BYTES_PER_CHAR = 4;
const HIGHEST_MAX_TOKENS = Math.max(
  ...INFERENCE_PURPOSES.map((purpose) => claudeMaxTokens(purpose, 'high')),
);

// Submit bound x the highest max_tokens any purpose is sent with x bytes a token (the synchronous meter's 3 chars a token, at 4 UTF-8 bytes a char).
export const BATCH_RESULTS_MAX_BYTES =
  BATCH_MAX_REQUESTS_PER_SUBMIT *
  HIGHEST_MAX_TOKENS *
  CHARS_PER_TOKEN_FLOOR *
  UTF8_MAX_BYTES_PER_CHAR;
