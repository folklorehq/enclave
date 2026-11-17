import { ConnectorSpecError } from '@folklore/errors';

export const SPEC_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

export async function readLimitedBody(response: Response): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.byteLength;
    if (size > SPEC_MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new ConnectorSpecError('spec_response_too_large');
    }
    chunks.push(chunk.value);
  }
  return Buffer.concat(chunks).toString('utf8');
}
