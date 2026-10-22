import type { Cache } from '@folklore/core';

export interface VectorCache {
  getVector(key: string): Promise<number[] | null>;
  setVector(key: string, vector: readonly number[]): Promise<void>;
}

export type LlmOperationCache = Cache & VectorCache;

/** Rounds to float32, the precision the index stores, so a hit and a miss return the same vector. */
export function float32Vector(vector: readonly number[]): number[] {
  return vector.map(Math.fround);
}

/** Decodes a sealed vector; anything that is not an array of finite numbers is null, never an error. */
export function parseVector(text: string): number[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  return parsed.every((item) => typeof item === 'number' && Number.isFinite(item))
    ? float32Vector(parsed as number[])
    : null;
}
