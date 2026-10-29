import type { ResourceScope } from './ResourceScopeStore.js';

export type ResourceAdmission = (externalId: string | undefined) => boolean;

export const ADMIT_ALL: ResourceAdmission = () => true;
const ADMIT_NONE: ResourceAdmission = () => false;

/** A fact with no resource id is dropped in selected mode, so a narrowing never admits the unknown. */
export function admissionOf(scope: ResourceScope): ResourceAdmission {
  if (scope.paused) return ADMIT_NONE;
  if (scope.mode === 'all') return ADMIT_ALL;
  const selected = new Set(scope.resourceIds);
  return (externalId) => externalId !== undefined && selected.has(externalId);
}
