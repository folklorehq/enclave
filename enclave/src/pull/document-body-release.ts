import type { DocumentBodyMode } from '@folklore/connectors';

// Empty on purpose and not yet wired to any source: a kind reads document bodies only once it is listed here, so the attested image states which kinds do.
export const DOCUMENT_BODY_RELEASE: ReadonlyMap<string, DocumentBodyMode> = new Map();

// These kinds emit bodies by construction, so while their mode is off the pull is declined outright.
export const BODY_GATED_KINDS: ReadonlySet<string> = new Set([
  'confluence',
  'google_drive',
  'microsoft365',
]);

export function documentBodyModeFor(
  kind: string,
  release: ReadonlyMap<string, DocumentBodyMode> = DOCUMENT_BODY_RELEASE,
): DocumentBodyMode {
  return release.get(kind) ?? 'off';
}
