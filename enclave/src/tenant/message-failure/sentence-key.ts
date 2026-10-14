import { createHash } from 'node:crypto';

const SENTENCE_KEY_HEX_LENGTH = 16;

/** The sentence-table key of an exact message: a hash prefix, so the table ships no message text. */
export function sentenceKey(message: string): string {
  return createHash('sha256')
    .update(message, 'utf8')
    .digest('hex')
    .slice(0, SENTENCE_KEY_HEX_LENGTH);
}
