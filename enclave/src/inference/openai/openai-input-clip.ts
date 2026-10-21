// Every token encodes at least one byte, so this many bytes can never exceed the model's token window.
export const OPENAI_EMBED_MAX_INPUT_BYTES = 8_191;

const UTF8_CONTINUATION_MASK = 0xc0;
const UTF8_CONTINUATION_BITS = 0x80;

/** Cuts at most `maxBytes` of UTF-8 from the head, on a code-point boundary, with no lone surrogate. */
export function clipUtf8(text: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  const encoded = Buffer.from(text, 'utf8');
  if (encoded.length <= maxBytes) return encoded.toString('utf8');
  let end = maxBytes;
  while (end > 0 && isContinuationByte(encoded[end])) end -= 1;
  return encoded.subarray(0, end).toString('utf8');
}

function isContinuationByte(byte: number | undefined): boolean {
  return byte !== undefined && (byte & UTF8_CONTINUATION_MASK) === UTF8_CONTINUATION_BITS;
}
