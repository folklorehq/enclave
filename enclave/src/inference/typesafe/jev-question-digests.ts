import type { DecisionSite } from '@folklore/contracts';

// Keyed by digest, so one site may register several sets.
export const JEV_QUESTION_SET_DIGESTS: ReadonlyMap<string, DecisionSite> = new Map([
  ['31715334fe07b5aa6b56073f7a65de1866092a8243b28955b02469692b518122', 'theme_tagging'],
  ['7d77f876896488d37b54724a677b25d93d8726521066eb1788dfcb0124593f61', 'theme_doctype'],
  ['c9fee351650c95a14c31fecc36515d5fd7dfb43228b6eac28329ea87ade66a21', 'wiki_relevance'],
  ['301d38568523242c68994da64a4dbf80b346d9d6909045252b42eb636ebeb57d', 'theme_merge_pair'],
  ['147389cac0bc21d5b454ebd383a0391c52e29a58d80e89172521262978b99a2d', 'theme_merge_adjudication'],
  ['260e119c1609c830cda00dc312b923daf3df678d646db83c0b774ca86fca37e0', 'association_judge'],
  ['0c476d52dc74b32bcd3327f6a3074a8f4203eaad71d51907ac95d59c365fe53a', 'wiki_visual_warrant'],
  ['83f87f05c0719341a81b782bcbbb709a6c863815bf778d56bd211f80ceece26f', 'citation_check'],
  ['ddd83a0e647bf0039800707b7ec12ce31ca592c33bd69fc21e871361133cf478', 'ingest_salience'],
  ['c46d0d5d630e179819ace1daa4f0e6d17a7043b81f09871a2da7fc4090d07571', 'ingest_sensitivity'],
]);
