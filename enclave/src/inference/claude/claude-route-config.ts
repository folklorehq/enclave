import { deepFreeze } from '@folklore/utils';
import type {
  InferenceEffort,
  InferencePurpose,
  ClaudeModelId,
  ShadowArm,
} from '@folklore/contracts';

// prettier-ignore
export const CLAUDE_ROUTE_IDENTITY = {"enabled":true,"organizationIdSha256":"33db0107520c9f427f15cb96fa19ba66c0660e1e268f59321ec4e165c493c38b","workspaceIdSha256":"c85508b0386c3af3347ce71e1a2872bbc7ce14de5d87c5d1ad0141a1d5332613","models":["claude-haiku-5-5","claude-opus-5-5","claude-sonnet-5-5"]} as const;

export type ClaudeCallGraph = 'v2' | 'reference';

export interface ClaudePurposeRoute {
  readonly model: ClaudeModelId;
  readonly effort: InferenceEffort;
}

export interface ClaudeArmConfig {
  readonly callGraph: ClaudeCallGraph;
  readonly purposes: Readonly<Partial<Record<InferencePurpose, ClaudePurposeRoute>>>;
}

export interface ClaudeRouteConfig {
  readonly identity: {
    readonly enabled: boolean;
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
    readonly models: readonly ClaudeModelId[];
  };
  readonly callGraph: ClaudeCallGraph;
  readonly arms: Readonly<Record<ShadowArm, ClaudeArmConfig>>;
  readonly shadowOrgIdSha256: string;
  readonly reviewSamplePercent: number;
}

const REVIEW_SAMPLE_PERCENT = 10;
// Empty on purpose: no organization is shadowed, so FOLKLORE_OWN_ORG_ID_SHA256 must never feed this.
const SHADOW_ORG_ID_SHA256 = '';

export const CLAUDE_ROUTE_CONFIG: ClaudeRouteConfig = deepFreeze({
  identity: CLAUDE_ROUTE_IDENTITY,
  callGraph: 'v2',
  arms: {
    R: { callGraph: 'reference', purposes: {} },
    B: { callGraph: 'v2', purposes: {} },
  },
  shadowOrgIdSha256: SHADOW_ORG_ID_SHA256,
  reviewSamplePercent: REVIEW_SAMPLE_PERCENT,
});
