import { timingSafeEqual } from 'node:crypto';

export type RoutingMode = 'payload' | 'url';

export interface RoutingAllowlistEntry {
  tenantId: string;
  source: string;
  mode: RoutingMode;
  hmac?: string;
  previousHmac?: string;
  expiresAt?: string;
}

export function routingHmacMessage(tenantId: string, source: string, mode: RoutingMode): string {
  return `${tenantId}:${source}:${mode}`;
}

export function normalizeRoutingAllowlist(value: unknown): readonly RoutingAllowlistEntry[] {
  if (!Array.isArray(value)) return [];
  const entries: RoutingAllowlistEntry[] = [];
  for (const candidate of value) {
    if (!candidate || typeof candidate !== 'object') continue;
    const item = candidate as Record<string, unknown>;
    if (
      typeof item['tenantId'] !== 'string' ||
      typeof item['source'] !== 'string' ||
      (item['mode'] !== 'payload' && item['mode'] !== 'url')
    ) {
      continue;
    }
    entries.push({
      tenantId: item['tenantId'],
      source: item['source'],
      mode: item['mode'],
      ...(typeof item['hmac'] === 'string' ? { hmac: item['hmac'] } : {}),
      ...(typeof item['previousHmac'] === 'string' ? { previousHmac: item['previousHmac'] } : {}),
      ...(typeof item['expiresAt'] === 'string' ? { expiresAt: item['expiresAt'] } : {}),
    });
  }
  return entries;
}

export function findRoutingAllowlistEntry(
  entries: readonly RoutingAllowlistEntry[],
  tenantId: string,
  source: string,
  mode: RoutingMode,
): RoutingAllowlistEntry | null {
  const entry = entries.find(
    (candidate) =>
      candidate.tenantId === tenantId && candidate.source === source && candidate.mode === mode,
  );
  if (!entry) return null;
  if (entry.expiresAt && Date.parse(entry.expiresAt) <= Date.now()) return null;
  return entry;
}

export function verifyRoutingHmac(
  provided: string,
  expected: string,
  previousExpected?: string,
): boolean {
  const candidates = [expected, ...(previousExpected ? [previousExpected] : [])];
  return candidates.some((candidate) => {
    const left = Buffer.from(provided, 'utf8');
    const right = Buffer.from(candidate, 'utf8');
    return left.length === right.length && timingSafeEqual(left, right);
  });
}
