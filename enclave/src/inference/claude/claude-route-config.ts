import { deepFreeze } from '@folklore/utils';
import type {
  InferenceEffort,
  InferencePurpose,
  ClaudeModelId,
  InferenceArmId,
} from '@folklore/contracts';

// prettier-ignore
export const CLAUDE_ROUTE_IDENTITY = {"enabled":true,"organizationIdSha256":"33db0107520c9f427f15cb96fa19ba66c0660e1e268f59321ec4e165c493c38b","workspaceIdSha256":"c85508b0386c3af3347ce71e1a2872bbc7ce14de5d87c5d1ad0141a1d5332613","models":["claude-haiku-5-5","claude-opus-5-5","claude-sonnet-5-5"]} as const;

export interface ClaudePurposeRoute {
  readonly model: ClaudeModelId;
  readonly effort: InferenceEffort;
}

export interface ClaudeArmConfig {
  readonly purposes: Readonly<Partial<Record<InferencePurpose, ClaudePurposeRoute>>>;
}

export interface ClaudeRouteConfig {
  readonly identity: {
    readonly enabled: boolean;
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
    readonly models: readonly ClaudeModelId[];
  };
  readonly arms: Readonly<Record<Exclude<InferenceArmId, 'D'>, ClaudeArmConfig>>;
  readonly reviewSamplePercent: number;
}

const REVIEW_SAMPLE_PERCENT = 10;

export const CLAUDE_ROUTE_CONFIG: ClaudeRouteConfig = deepFreeze({
  identity: CLAUDE_ROUTE_IDENTITY,
  arms: {
    R: { purposes: {} },
    B: { purposes: {} },
  },
  reviewSamplePercent: REVIEW_SAMPLE_PERCENT,
});
