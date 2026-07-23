import { createHmac } from 'crypto';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';

const ssm = new SSMClient({});

const DISPATCHER_AUTH_SSM_PATH = '/folklore/shared/dispatcher-auth-secret';
const CACHE_TTL_MS = 5 * 60 * 1000;

let cache: { secret: string; expiresAt: number } | null = null;

// Single source of truth: dispatcher.ts and lambdas/handler.ts both import this rather than
// each reading the secret their own way, so the HMAC they compute can't silently diverge.
export async function fetchDispatcherAuthSecret(): Promise<string | null> {
  if (cache && Date.now() < cache.expiresAt) return cache.secret;

  try {
    const result = await ssm.send(
      new GetParameterCommand({ Name: DISPATCHER_AUTH_SSM_PATH, WithDecryption: true }),
    );
    const secret = result.Parameter?.Value ?? null;
    if (secret) cache = { secret, expiresAt: Date.now() + CACHE_TTL_MS };
    return secret;
  } catch {
    return null;
  }
}

export function computeDispatcherAuthHmac(
  tenantId: string,
  source: string,
  secret: string,
): string {
  return createHmac('sha256', secret).update(`${tenantId}:${source}`).digest('hex');
}
