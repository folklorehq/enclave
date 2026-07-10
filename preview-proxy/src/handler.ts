import { previewRequestSchema, previewResponseSchema } from '@folklore/contracts';
import type { PreviewService } from './preview-service.js';
import type { RateLimiter } from './rate-limiter.js';

export interface HttpReply {
  status: number;
  body: string;
}

export async function handlePreviewRequest(
  rawBody: string,
  service: PreviewService,
  rateLimiter: RateLimiter,
): Promise<HttpReply> {
  let json: unknown;
  try {
    json = JSON.parse(rawBody);
  } catch {
    return { status: 400, body: JSON.stringify({ error: 'invalid json' }) };
  }

  const parsed = previewRequestSchema.safeParse(json);
  if (!parsed.success) return { status: 400, body: JSON.stringify({ error: 'invalid request' }) };

  const host = hostOf(parsed.data.url);
  if (host && !rateLimiter.check(host)) {
    return { status: 429, body: JSON.stringify({ error: 'rate limited' }) };
  }

  const preview = await service.preview(parsed.data.url);
  return { status: 200, body: JSON.stringify(previewResponseSchema.parse({ preview })) };
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}
