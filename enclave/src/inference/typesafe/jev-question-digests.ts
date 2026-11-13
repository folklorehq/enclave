import type { DecisionSite } from '@folklore/contracts';

// Keyed by digest, so one site may register several sets.
export const JEV_QUESTION_SET_DIGESTS: ReadonlyMap<string, DecisionSite> = new Map([
  ['31715334fe07b5aa6b56073f7a65de1866092a8243b28955b02469692b518122', 'theme_tagging'],
]);
