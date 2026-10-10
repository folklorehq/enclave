import { createHash, createHmac } from 'node:crypto';

// Turns a cache key into the tenant-keyed name stored outside the enclave.
export interface LlmCacheNamer {
  llmCacheName(cacheKey: string): string;
}

// Same input under the same model + prompt version collides on the same key, so a model or prompt
// change deterministically invalidates (folds into provenance too — determinism cross-cutting note).
export function llmCacheKey(
  modelId: string,
  promptVersion: string,
  canonicalInput: string,
): string {
  return createHash('sha256')
    .update(`${modelId}\n${promptVersion}\n${canonicalInput}`)
    .digest('hex');
}

export function llmCacheObjectName(nameKey: Buffer, cacheKey: string): string {
  return createHmac('sha256', nameKey).update(cacheKey).digest('hex');
}
