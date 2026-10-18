import type {
  ClaudeEffort,
  ClaudeInferencePurpose,
  ClaudeModelId,
  ShadowArm,
} from '@folklore/contracts';

// prettier-ignore
export const CLAUDE_ROUTE_IDENTITY = {"enabled":true,"organizationIdSha256":"f076b928103bd31907daba3bc5a5814a7da2eb9bd7e20106e1d6477b654083bf","workspaceIdSha256":"8d9ac963f265876277a266eca3956a861fde4c44ce4a6005acb81e825e2af4d2","models":["claude-haiku-5-5","claude-opus-5-5","claude-sonnet-5-5"]} as const;

export type ClaudeCallGraph = 'v2' | 'reference';

export interface ClaudePurposeRoute {
  readonly model: ClaudeModelId;
  readonly effort: ClaudeEffort;
}

export interface ClaudeArmConfig {
  readonly callGraph: ClaudeCallGraph;
  readonly purposes: Readonly<Partial<Record<ClaudeInferencePurpose, ClaudePurposeRoute>>>;
}

export interface ClaudeRouteConfig {
  readonly identity: {
    readonly enabled: boolean;
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
    readonly models: readonly ClaudeModelId[];
  };
  readonly callGraph: ClaudeCallGraph;
  readonly purposes: Readonly<Record<ClaudeInferencePurpose, ClaudePurposeRoute>>;
  readonly arms: Readonly<Record<ShadowArm, ClaudeArmConfig>>;
  readonly shadowOrgIdSha256: string;
  readonly reviewSamplePercent: number;
}

const HAIKU: ClaudeModelId = 'claude-haiku-5-5';
const SONNET: ClaudeModelId = 'claude-sonnet-5-5';
const OPUS: ClaudeModelId = 'claude-opus-5-5';
const REVIEW_SAMPLE_PERCENT = 10;
const SHADOW_ORG_ID_SHA256 = '810e451ec9c7513f42ad026c53e97bafa4995188f1b8b2bcefb6713461a5df2c';

const route = (model: ClaudeModelId, effort: ClaudeEffort): ClaudePurposeRoute => ({
  model,
  effort,
});

const OPUS_MEDIUM = route(OPUS, 'medium');
const OPUS_LOW = route(OPUS, 'low');

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const member of Object.values(value)) deepFreeze(member);
  }
  return value;
}

export const CLAUDE_ROUTE_CONFIG: ClaudeRouteConfig = deepFreeze({
  identity: CLAUDE_ROUTE_IDENTITY,
  callGraph: 'v2',
  purposes: {
    wiki_outline: OPUS_MEDIUM,
    wiki_section: route(SONNET, 'medium'),
    wiki_revise: route(SONNET, 'medium'),
    wiki_visual_warrant: route(SONNET, 'low'),
    wiki_visual_draw: route(SONNET, 'low'),
    wiki_article: route(SONNET, 'medium'),
    team_onboarding: route(SONNET, 'medium'),
    wiki_review: OPUS_MEDIUM,
    wiki_critique: OPUS_MEDIUM,
    citation_check: route(SONNET, 'low'),
    theme_merge: route(SONNET, 'low'),
    wiki_relevance: route(HAIKU, 'low'),
    wiki_recovery: route(HAIKU, 'low'),
    wiki_repair: route(HAIKU, 'low'),
    theme_tagging: route(HAIKU, 'low'),
    theme_topic_naming: route(HAIKU, 'low'),
    theme_aggregate_naming: route(HAIKU, 'low'),
    theme_doctype: route(HAIKU, 'low'),
    association_judge: route(SONNET, 'low'),
    answer: route(SONNET, 'medium'),
    wiki_delta: route(SONNET, 'medium'),
    wiki_section_add: route(SONNET, 'medium'),
    wiki_section_long: route(SONNET, 'medium'),
    wiki_outline_long: OPUS_MEDIUM,
  },
  arms: {
    R: {
      callGraph: 'reference',
      purposes: allPurposes(OPUS_MEDIUM),
    },
    B: {
      callGraph: 'v2',
      purposes: allPurposes(OPUS_LOW),
    },
  },
  shadowOrgIdSha256: SHADOW_ORG_ID_SHA256,
  reviewSamplePercent: REVIEW_SAMPLE_PERCENT,
});

function allPurposes(
  value: ClaudePurposeRoute,
): Readonly<Record<ClaudeInferencePurpose, ClaudePurposeRoute>> {
  return {
    wiki_outline: value,
    wiki_section: value,
    wiki_revise: value,
    wiki_visual_warrant: value,
    wiki_visual_draw: value,
    wiki_article: value,
    team_onboarding: value,
    wiki_review: value,
    wiki_critique: value,
    citation_check: value,
    theme_merge: value,
    wiki_relevance: value,
    wiki_recovery: value,
    wiki_repair: value,
    theme_tagging: value,
    theme_topic_naming: value,
    theme_aggregate_naming: value,
    theme_doctype: value,
    association_judge: value,
    answer: value,
    wiki_delta: value,
    wiki_section_add: value,
    wiki_section_long: value,
    wiki_outline_long: value,
  };
}
