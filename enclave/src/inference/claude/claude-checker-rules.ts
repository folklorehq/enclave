import type { ClaudeInferencePurpose, ClaudeModelId } from '@folklore/contracts';
import { CLAUDE_WRITING_PURPOSES } from './claude-purpose-limits.js';
import { ClaudeRouteConfigError } from './claude-route-errors.js';

interface RoutedPurposes {
  readonly purposes: Readonly<Record<ClaudeInferencePurpose, { readonly model: ClaudeModelId }>>;
}

export interface CheckerRule {
  readonly reads: ReadonlySet<ClaudeInferencePurpose>;
  readonly alwaysReads?: ReadonlySet<ClaudeInferencePurpose>;
  readonly fallback?: ClaudeInferencePurpose;
}

export type CheckerRules = Readonly<Partial<Record<ClaudeInferencePurpose, CheckerRule>>>;

export const PAGE_TEXT_WRITERS: ReadonlySet<ClaudeInferencePurpose> = new Set([
  'wiki_section',
  'wiki_section_long',
  'wiki_delta',
  'wiki_section_add',
  'wiki_page_revise',
]);

export const ARTICLE_TEXT_WRITERS: ReadonlySet<ClaudeInferencePurpose> = new Set([
  'wiki_article',
  'wiki_article_long',
  'team_onboarding',
  'team_onboarding_long',
  'wiki_section',
  'wiki_section_long',
  'wiki_revise',
  'wiki_recovery',
]);

const CRITIQUE_READS: ReadonlySet<ClaudeInferencePurpose> = new Set([
  ...CLAUDE_WRITING_PURPOSES,
  'wiki_recovery',
]);

export const CHECKER_RULES: CheckerRules = {
  wiki_review: { reads: CLAUDE_WRITING_PURPOSES },
  wiki_critique: { reads: CRITIQUE_READS },
  wiki_page_check: {
    reads: PAGE_TEXT_WRITERS,
    alwaysReads: new Set<ClaudeInferencePurpose>(['wiki_section', 'wiki_page_revise']),
    fallback: 'wiki_review',
  },
  wiki_article_check: {
    reads: ARTICLE_TEXT_WRITERS,
    alwaysReads: new Set<ClaudeInferencePurpose>(['team_onboarding', 'wiki_article']),
    fallback: 'wiki_critique',
  },
};

export const CLAUDE_CHECK_PURPOSES: ReadonlySet<ClaudeInferencePurpose> = new Set(
  Object.keys(CHECKER_RULES) as ClaudeInferencePurpose[],
);

function modelsOf(
  config: RoutedPurposes,
  purposes: ReadonlySet<ClaudeInferencePurpose>,
): Set<ClaudeModelId> {
  return new Set([...purposes].map((purpose) => config.purposes[purpose].model));
}

function isSuperset(
  outer: ReadonlySet<ClaudeInferencePurpose>,
  inner: ReadonlySet<ClaudeInferencePurpose>,
): boolean {
  return [...inner].every((purpose) => outer.has(purpose));
}

function assertFallbackValid(rule: CheckerRule, rules: CheckerRules): void {
  const fallback = rule.fallback === undefined ? undefined : rules[rule.fallback];
  if (
    fallback === undefined ||
    fallback.fallback !== undefined ||
    !isSuperset(fallback.reads, rule.reads)
  ) {
    throw new ClaudeRouteConfigError('check_fallback_invalid');
  }
}

function assertRule(
  config: RoutedPurposes,
  checker: ClaudeInferencePurpose,
  rule: CheckerRule,
  rules: CheckerRules,
): void {
  if (rule.fallback !== undefined) assertFallbackValid(rule, rules);
  const staticReads = rule.fallback === undefined ? rule.reads : (rule.alwaysReads ?? new Set());
  if (modelsOf(config, staticReads).has(config.purposes[checker].model)) {
    throw new ClaudeRouteConfigError('check_model_shared');
  }
}

export function assertCheckerRules(
  config: RoutedPurposes,
  rules: CheckerRules = CHECKER_RULES,
): void {
  for (const [checker, rule] of Object.entries(rules)) {
    assertRule(config, checker as ClaudeInferencePurpose, rule, rules);
  }
}
