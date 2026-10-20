import { deepFreeze } from '@folklore/utils';
import type {
  InferenceEffort,
  InferencePurpose,
  ClaudeModelId,
  ShadowArm,
} from '@folklore/contracts';

// prettier-ignore
export const CLAUDE_ROUTE_IDENTITY = {"enabled":true,"organizationIdSha256":"f076b928103bd31907daba3bc5a5814a7da2eb9bd7e20106e1d6477b654083bf","workspaceIdSha256":"8d9ac963f265876277a266eca3956a861fde4c44ce4a6005acb81e825e2af4d2","models":["claude-haiku-5-5","claude-opus-5-5","claude-sonnet-5-5"]} as const;

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
