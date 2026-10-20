import {
  INFERENCE_MODEL_CATALOG,
  inferenceTimeoutMs,
  INFERENCE_WRITING_PURPOSES,
  type ClaudeModelId,
  type InferenceEffort,
  type InferenceModelCatalogEntry,
  type InferencePurpose,
} from '@folklore/contracts';
import { ClaudeRouteConfigError } from './claude-route-errors.js';

const THINKING_RATIO: Readonly<Record<InferenceEffort, number>> = {
  low: 1,
  medium: 2,
  high: 3,
};

export const HAIKU_MAX_INPUT_TOKENS = 100_000;

export const CLAUDE_WRITING_PURPOSES: ReadonlySet<InferencePurpose> = INFERENCE_WRITING_PURPOSES;

export interface ClaudePurposeLimit {
  readonly visibleMax: number;
  readonly cacheMark: boolean;
}

const limit = (visibleMax: number, cacheMark = false): ClaudePurposeLimit => ({
  visibleMax,
  cacheMark,
});

export const CLAUDE_PURPOSE_LIMITS: Readonly<Record<InferencePurpose, ClaudePurposeLimit>> = {
  wiki_outline: limit(4_096),
  wiki_section: limit(4_096, true),
  wiki_revise: limit(8_192),
  wiki_visual_warrant: limit(1_024),
  wiki_visual_draw: limit(4_096),
  wiki_article: limit(8_192),
  team_onboarding: limit(8_192),
  wiki_review: limit(4_096),
  wiki_critique: limit(4_096),
  citation_check: limit(1_024),
  theme_merge: limit(1_024),
  wiki_relevance: limit(512),
  wiki_recovery: limit(2_048),
  wiki_repair: limit(2_048),
  theme_tagging: limit(1_024),
  theme_topic_naming: limit(512),
  theme_aggregate_naming: limit(512),
  theme_doctype: limit(256),
  association_judge: limit(1_024),
  answer: limit(2_048),
  wiki_delta: limit(4_096, true),
  wiki_section_add: limit(4_096, true),
  wiki_section_long: limit(4_096, true),
  wiki_outline_long: limit(4_096),
  wiki_page_check: limit(8_192),
  wiki_page_revise: limit(8_192),
  wiki_article_check: limit(8_192),
  wiki_article_long: limit(8_192),
  team_onboarding_long: limit(8_192),
};

export function claudeMaxTokens(purpose: InferencePurpose, effort: InferenceEffort): number {
  return Math.ceil(CLAUDE_PURPOSE_LIMITS[purpose].visibleMax * (1 + THINKING_RATIO[effort]));
}

export function claudeTimeoutMs(purpose: InferencePurpose, model: ClaudeModelId): number {
  const entry: InferenceModelCatalogEntry = INFERENCE_MODEL_CATALOG[model];
  const timeoutMs = inferenceTimeoutMs(entry, purpose);
  if (timeoutMs === undefined) throw new ClaudeRouteConfigError('timeout_unmapped');
  return timeoutMs;
}
