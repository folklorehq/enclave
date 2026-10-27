import type { CodebaseConsentResolution } from './GitHubCodebaseConnectionResolver.js';

export interface TombstoneMarker {
  readonly tombstoneId: string | null;
  readonly allRetiredEpoch: number;
}

export const UNRECORDED_TOMBSTONE_MARKER: TombstoneMarker = {
  tombstoneId: null,
  allRetiredEpoch: 0,
};

export type CodeGraphSelection =
  | { readonly mode: 'all'; readonly revision: number }
  | {
      readonly mode: 'selected';
      readonly repositoryIds: ReadonlySet<string>;
      readonly revision: number;
    };

export type CodeGraphConsent =
  | {
      readonly active: false;
      readonly reason: 'capability_disabled' | 'capability_absent' | 'unresolved';
    }
  | {
      readonly active: true;
      readonly generation: string;
      readonly deploymentId: string;
      readonly tombstoneMarker: TombstoneMarker;
      readonly selection: CodeGraphSelection;
    };

const UNRESOLVED: CodeGraphConsent = { active: false, reason: 'unresolved' };

export async function resolveCodeGraphConsent(
  resolve: () => Promise<CodebaseConsentResolution>,
  readTombstoneMarker: () => Promise<TombstoneMarker>,
): Promise<CodeGraphConsent> {
  const marker = await settled(readTombstoneMarker);
  try {
    const resolution = await resolve();
    if (resolution.outcome === 'ready') return activeConsent(resolution, marker);
    if (resolution.outcome === 'not_ready') return inactiveConsent(resolution.reason);
    return UNRESOLVED;
  } catch {
    return UNRESOLVED;
  }
}

async function settled(
  readTombstoneMarker: () => Promise<TombstoneMarker>,
): Promise<TombstoneMarker | null> {
  try {
    return await readTombstoneMarker();
  } catch {
    return null;
  }
}

function activeConsent(
  resolution: Extract<CodebaseConsentResolution, { outcome: 'ready' }>,
  marker: TombstoneMarker | null,
): CodeGraphConsent {
  if (marker === null) return UNRESOLVED;
  const { selection } = resolution;
  return {
    active: true,
    generation: resolution.capabilityGeneration,
    deploymentId: resolution.deploymentId,
    tombstoneMarker: marker,
    selection:
      selection.mode === 'all'
        ? { mode: 'all', revision: selection.revision }
        : {
            mode: 'selected',
            revision: selection.revision,
            repositoryIds: new Set(
              selection.repositories.map((repository) => String(repository.id)),
            ),
          },
  };
}

function inactiveConsent(reason: string): CodeGraphConsent {
  if (reason === 'codebase_capability_disabled') {
    return { active: false, reason: 'capability_disabled' };
  }
  if (reason === 'codebase_capability_missing' || reason === 'codebase_parent_missing') {
    return { active: false, reason: 'capability_absent' };
  }
  return UNRESOLVED;
}
