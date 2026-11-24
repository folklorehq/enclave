import { INFERENCE_CHECKER_RULES, type InferencePurpose } from '@folklore/contracts';

export const CHECKER_RULES = INFERENCE_CHECKER_RULES;

export const CLAUDE_CHECK_PURPOSES: ReadonlySet<InferencePurpose> = new Set(
  Object.keys(CHECKER_RULES) as InferencePurpose[],
);
