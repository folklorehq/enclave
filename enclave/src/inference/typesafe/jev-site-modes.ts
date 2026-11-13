import { deepFreeze, sha256Hex } from '@folklore/utils';
import {
  SHADOW_ONLY_SITES,
  type DecisionSite,
  type DecisionSiteMode,
  type ModeFor,
} from '@folklore/contracts';
import {
  TYPESAFE_DECISION_ROUTE_STATE,
  type TypeSafeDecisionRouteState,
} from './typesafe-decision-route-state.js';

export interface JevSitePolicy<M extends DecisionSiteMode> {
  readonly mode: M;
  readonly jevOrgIdSha256s: readonly string[];
}

export type JevSitePolicies = { readonly [S in DecisionSite]: JevSitePolicy<ModeFor<S>> };

const off = (): JevSitePolicy<'off'> => ({ mode: 'off', jevOrgIdSha256s: [] });

// not yet wired: every site stays off until its shadow step.
export const JEV_SITE_POLICIES = deepFreeze({
  theme_tagging: off(),
  theme_doctype: off(),
  wiki_relevance: off(),
  theme_merge_adjudication: off(),
  association_judge: off(),
  wiki_visual_warrant: off(),
  citation_check: off(),
  ingest_salience: off(),
  ingest_sensitivity: off(),
  theme_merge_pair: off(),
  theme_disposition: off(),
} satisfies JevSitePolicies);

function inOrgScope(state: TypeSafeDecisionRouteState, orgHash: string): boolean {
  if (state.kind !== 'enabled') return false;
  return state.identity.orgScope === 'all_orgs' || state.identity.orgIdSha256s.includes(orgHash);
}

function resolvedMode(
  site: DecisionSite,
  configured: JevSitePolicy<DecisionSiteMode>,
  orgHash: string,
): DecisionSiteMode {
  if (configured.mode !== 'shadow' && configured.mode !== 'jev') return 'off';
  const isShadowOnly = (SHADOW_ONLY_SITES as readonly string[]).includes(site);
  const decides = configured.mode === 'jev' && !isShadowOnly;
  return decides && configured.jevOrgIdSha256s.includes(orgHash) ? 'jev' : 'shadow';
}

/** 'off' unless the route is enabled and the org is in scope; shadow-only sites never exceed 'shadow'. */
export function jevSiteMode<S extends DecisionSite>(
  site: S,
  orgId: string,
  state: TypeSafeDecisionRouteState = TYPESAFE_DECISION_ROUTE_STATE,
  policies: JevSitePolicies = JEV_SITE_POLICIES,
): ModeFor<S> {
  const orgHash = sha256Hex(orgId);
  if (!inOrgScope(state, orgHash)) return 'off' as ModeFor<S>;
  const configured: JevSitePolicy<DecisionSiteMode> | undefined = policies[site];
  if (configured === undefined) return 'off' as ModeFor<S>;
  return resolvedMode(site, configured, orgHash) as ModeFor<S>;
}
