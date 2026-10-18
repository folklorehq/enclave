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
const SHADOW_ORG_ID_SHA256 = '';

const route = (model: ClaudeModelId, effort: ClaudeEffort): ClaudePurposeRoute => ({
  model,
  effort,
});

const OPUS_MEDIUM = route(OPUS, 'medium');

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
    theme_topic_naming: route(SONNET, 'medium'),
    theme_aggregate_naming: route(SONNET, 'medium'),
    theme_doctype: route(HAIKU, 'low'),
    association_judge: route(SONNET, 'low'),
    answer: route(SONNET, 'medium'),
    wiki_delta: route(SONNET, 'medium'),
    wiki_section_add: route(SONNET, 'medium'),
    wiki_section_long: route(SONNET, 'medium'),
    wiki_outline_long: OPUS_MEDIUM,
    wiki_page_check: OPUS_MEDIUM,
    wiki_page_revise: route(SONNET, 'medium'),
    wiki_article_check: OPUS_MEDIUM,
    wiki_article_long: route(SONNET, 'medium'),
    team_onboarding_long: route(SONNET, 'medium'),
  },
  arms: {
    R: { callGraph: 'reference', purposes: {} },
    B: { callGraph: 'v2', purposes: {} },
  },
  shadowOrgIdSha256: SHADOW_ORG_ID_SHA256,
  reviewSamplePercent: REVIEW_SAMPLE_PERCENT,
});
