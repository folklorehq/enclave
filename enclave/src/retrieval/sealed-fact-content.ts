export interface SealedFactContent {
  readonly body: string;
  readonly title: string | null;
}

/** The body and structured title of a decrypted fact record; null when there is no record. */
export function sealedFactContent(
  record: Record<string, unknown> | null,
): SealedFactContent | null {
  if (record === null) return null;
  const content = record['content'] as Record<string, unknown> | undefined;
  const body = content?.['body'];
  const title = content?.['title'];
  return {
    body: typeof body === 'string' ? body : '',
    title: typeof title === 'string' ? title : null,
  };
}
