export const OPENAI_SUCCESS_BODY_MAX_BYTES = 262_144;
export const OPENAI_ERROR_BODY_MAX_BYTES = 16_384;

export class OpenAIBodyTooLargeError extends Error {
  constructor() {
    super('openai_response_body_too_large');
    this.name = 'OpenAIBodyTooLargeError';
  }
}

/** Reads at most `maxBytes` and cancels the stream past that, so an upstream cannot make the enclave buffer without bound. */
export async function readBoundedText(
  response: Pick<Response, 'body'>,
  maxBytes: number,
): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new OpenAIBodyTooLargeError();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function discardBody(response: Pick<Response, 'body'>): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}
