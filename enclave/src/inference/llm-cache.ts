import { createHash } from 'node:crypto';

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
