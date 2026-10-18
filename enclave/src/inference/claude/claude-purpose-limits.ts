import type { ClaudeEffort, ClaudeInferencePurpose, ClaudeModelId } from '@folklore/contracts';
import { ClaudeRouteConfigError } from './claude-route-errors.js';

const THINKING_RATIO: Readonly<Record<ClaudeEffort, number>> = {
  low: 1,
  medium: 2,
  high: 3,
};

export const HAIKU_MAX_INPUT_TOKENS = 100_000;

export const CLAUDE_WRITING_PURPOSES: ReadonlySet<ClaudeInferencePurpose> = new Set([
  'wiki_section',
  'wiki_revise',
  'wiki_article',
  'team_onboarding',
  'wiki_visual_draw',
  'wiki_delta',
  'wiki_section_add',
  'wiki_section_long',
  'wiki_page_revise',
  'wiki_article_long',
  'team_onboarding_long',
]);

export interface ClaudePurposeLimit {
  readonly visibleMax: number;
  readonly cacheMark: boolean;
}

const limit = (visibleMax: number, cacheMark = false): ClaudePurposeLimit => ({
  visibleMax,
  cacheMark,
});

export const CLAUDE_PURPOSE_LIMITS: Readonly<Record<ClaudeInferencePurpose, ClaudePurposeLimit>> = {
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

const INTERACTIVE_MS = 40_000;
const SMALL_MS = 60_000;
const SMALL_OPUS_MS = 120_000;
const MEDIUM_MS = 180_000;
const MEDIUM_OPUS_MS = 300_000;
const LARGE_MS = 420_000;
const LARGE_OPUS_MS = 480_000;

const SONNET_AND_OPUS = (sonnetMs: number, opusMs: number) => ({
  'claude-sonnet-5-5': sonnetMs,
  'claude-opus-5-5': opusMs,
});
const HAIKU_SONNET_AND_OPUS = (smallModelMs: number, opusMs: number) => ({
  'claude-haiku-5-5': smallModelMs,
  'claude-sonnet-5-5': smallModelMs,
  'claude-opus-5-5': opusMs,
});
const HAIKU_AND_OPUS = (haikuMs: number, opusMs: number) => ({
  'claude-haiku-5-5': haikuMs,
  'claude-opus-5-5': opusMs,
});

export const CLAUDE_PURPOSE_TIMEOUT_MS: Readonly<
  Record<ClaudeInferencePurpose, Readonly<Partial<Record<ClaudeModelId, number>>>>
> = {
  wiki_outline: HAIKU_SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_section: HAIKU_SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_revise: SONNET_AND_OPUS(LARGE_MS, LARGE_OPUS_MS),
  wiki_visual_warrant: SONNET_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  wiki_visual_draw: SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_article: HAIKU_SONNET_AND_OPUS(LARGE_MS, LARGE_OPUS_MS),
  team_onboarding: HAIKU_SONNET_AND_OPUS(LARGE_MS, LARGE_OPUS_MS),
  wiki_review: SONNET_AND_OPUS(LARGE_MS, MEDIUM_OPUS_MS),
  wiki_critique: SONNET_AND_OPUS(LARGE_MS, MEDIUM_OPUS_MS),
  citation_check: SONNET_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  theme_merge: SONNET_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  wiki_relevance: HAIKU_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  wiki_recovery: HAIKU_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  wiki_repair: HAIKU_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  theme_tagging: HAIKU_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  theme_topic_naming: SONNET_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  theme_aggregate_naming: SONNET_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  theme_doctype: HAIKU_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  association_judge: SONNET_AND_OPUS(SMALL_MS, SMALL_OPUS_MS),
  answer: SONNET_AND_OPUS(INTERACTIVE_MS, INTERACTIVE_MS),
  wiki_delta: HAIKU_SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_section_add: HAIKU_SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_section_long: SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_outline_long: SONNET_AND_OPUS(MEDIUM_MS, MEDIUM_OPUS_MS),
  wiki_page_check: SONNET_AND_OPUS(LARGE_MS, MEDIUM_OPUS_MS),
  wiki_page_revise: HAIKU_SONNET_AND_OPUS(LARGE_MS, LARGE_OPUS_MS),
  wiki_article_check: SONNET_AND_OPUS(LARGE_MS, MEDIUM_OPUS_MS),
  wiki_article_long: SONNET_AND_OPUS(LARGE_MS, LARGE_OPUS_MS),
  team_onboarding_long: SONNET_AND_OPUS(LARGE_MS, LARGE_OPUS_MS),
};

export function claudeMaxTokens(purpose: ClaudeInferencePurpose, effort: ClaudeEffort): number {
  return Math.ceil(CLAUDE_PURPOSE_LIMITS[purpose].visibleMax * (1 + THINKING_RATIO[effort]));
}

export function claudeTimeoutMs(purpose: ClaudeInferencePurpose, model: ClaudeModelId): number {
  const timeoutMs = CLAUDE_PURPOSE_TIMEOUT_MS[purpose][model];
  if (timeoutMs === undefined) throw new ClaudeRouteConfigError('timeout_unmapped');
  return timeoutMs;
}
