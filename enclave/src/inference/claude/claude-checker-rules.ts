import {
  INFERENCE_ARTICLE_TEXT_WRITERS,
  INFERENCE_CHECKER_RULES,
  INFERENCE_PAGE_TEXT_WRITERS,
  type InferencePurpose,
} from '@folklore/contracts';

export const PAGE_TEXT_WRITERS = INFERENCE_PAGE_TEXT_WRITERS;
export const ARTICLE_TEXT_WRITERS = INFERENCE_ARTICLE_TEXT_WRITERS;
export const CHECKER_RULES = INFERENCE_CHECKER_RULES;

export const CLAUDE_CHECK_PURPOSES: ReadonlySet<InferencePurpose> = new Set(
  Object.keys(CHECKER_RULES) as InferencePurpose[],
);
