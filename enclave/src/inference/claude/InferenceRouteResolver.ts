import { createHash } from 'node:crypto';
import {
  CLAUDE_INFERENCE_PURPOSES,
  CLAUDE_ROUTE_MODEL_IDS,
  type ClaudeArmId,
  type ClaudeEffort,
  type ClaudeInferencePurpose,
  type ClaudeModelId,
  type InferenceModelRole,
  type ShadowArm,
} from '@folklore/contracts';
import {
  DEFAULT_ARM,
  inferencePurposeScope,
  type InferencePurposeContext,
} from '../InferencePurposeScope.js';
import {
  CLAUDE_ROUTE_CONFIG,
  type ClaudeCallGraph,
  type ClaudeRouteConfig,
} from './claude-route-config.js';
import { CLAUDE_WRITING_PURPOSES, claudeTimeoutMs } from './claude-purpose-limits.js';
import { CLAUDE_ROUTE_CONFIG_INVALID, ClaudeRouteConfigError } from './claude-route-errors.js';

export type InferenceRoute =
  | { readonly kind: 'aci' }
  | {
      readonly kind: 'claude';
      readonly purpose: ClaudeInferencePurpose;
      readonly model: ClaudeModelId;
      readonly effort: ClaudeEffort;
      readonly arm: ClaudeArmId;
      readonly untagged: boolean;
    };

export type ClaudeRoute = Extract<InferenceRoute, { kind: 'claude' }>;

export const ACI_ROUTE: InferenceRoute = Object.freeze({ kind: 'aci' });
export const UPSTREAM_KEY_PREFIX = 'anthropic/';

const SHA256_HEX = /^[0-9a-f]{64}$/;
const CHECK_PURPOSES: readonly ClaudeInferencePurpose[] = ['wiki_review', 'wiki_critique'];
const ARM_IDS: readonly string[] = ['B', 'R'];

const CLAUDE_DEFAULT_PURPOSE_BY_ROLE: Readonly<
  Record<Exclude<InferenceModelRole, 'embed'>, ClaudeInferencePurpose>
> = {
  generate: 'wiki_article',
  critique: 'wiki_critique',
  judge: 'wiki_relevance',
};

function invalid(rule: string): never {
  throw new ClaudeRouteConfigError(rule);
}

function assertIdentity(identity: ClaudeRouteConfig['identity']): void {
  if (identity.enabled && !SHA256_HEX.test(identity.organizationIdSha256)) {
    invalid('organization_hash');
  }
  if (identity.workspaceIdSha256 !== '' && !SHA256_HEX.test(identity.workspaceIdSha256)) {
    invalid('workspace_hash');
  }
}

function assertCheckersDifferFromWriters(config: ClaudeRouteConfig): void {
  const writers = new Set(
    [...CLAUDE_WRITING_PURPOSES].map((purpose) => config.purposes[purpose].model),
  );
  if (CHECK_PURPOSES.some((purpose) => writers.has(config.purposes[purpose].model))) {
    invalid('check_model_shared');
  }
}

function assertPairResolvable(
  identity: ClaudeRouteConfig['identity'],
  purpose: ClaudeInferencePurpose,
  model: ClaudeModelId,
): void {
  if (!identity.models.includes(model)) invalid('model_not_allowed');
  try {
    claudeTimeoutMs(purpose, model);
  } catch {
    invalid('timeout_unmapped');
  }
}

function assertModelsAndTimeouts(config: ClaudeRouteConfig): void {
  const { identity } = config;
  if (!identity.models.every((model) => CLAUDE_ROUTE_MODEL_IDS.includes(model))) {
    invalid('model_not_in_allowlist');
  }
  for (const purpose of CLAUDE_INFERENCE_PURPOSES) {
    assertPairResolvable(identity, purpose, config.purposes[purpose].model);
  }
  for (const arm of Object.values(config.arms)) {
    for (const [purpose, route] of Object.entries(arm.purposes)) {
      assertPairResolvable(identity, purpose as ClaudeInferencePurpose, route.model);
    }
  }
}

function assertArms(config: ClaudeRouteConfig): void {
  if (Object.keys(config.arms).sort().join() !== ARM_IDS.join()) invalid('arms_invalid');
  const known = new Set<string>(CLAUDE_INFERENCE_PURPOSES);
  for (const arm of Object.values(config.arms)) {
    if (!Object.keys(arm.purposes).every((purpose) => known.has(purpose))) invalid('arm_purpose');
  }
}

export function assertClaudeRouteConfig(config: ClaudeRouteConfig): void {
  assertIdentity(config.identity);
  assertArms(config);
  assertCheckersDifferFromWriters(config);
  assertModelsAndTimeouts(config);
}

function disabledCopy(config: ClaudeRouteConfig): ClaudeRouteConfig {
  return { ...config, identity: { ...config.identity, enabled: false } };
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export class InferenceRouteResolver {
  readonly #config: ClaudeRouteConfig;
  readonly #invalidReason: string | undefined;

  constructor(config: ClaudeRouteConfig = CLAUDE_ROUTE_CONFIG) {
    try {
      assertClaudeRouteConfig(config);
      this.#config = config;
      this.#invalidReason = undefined;
    } catch (error) {
      this.#config = disabledCopy(config);
      this.#invalidReason = error instanceof Error ? error.message : CLAUDE_ROUTE_CONFIG_INVALID;
    }
  }

  get enabled(): boolean {
    return this.#config.identity.enabled && this.#invalidReason === undefined;
  }

  get invalidReason(): string | undefined {
    return this.#invalidReason;
  }

  resolve(role: InferenceModelRole, scope: InferencePurposeContext | undefined): InferenceRoute {
    if (role === 'embed' || !this.enabled) return ACI_ROUTE;
    const purpose = scope?.purpose ?? CLAUDE_DEFAULT_PURPOSE_BY_ROLE[role];
    const arm = scope?.arm ?? DEFAULT_ARM;
    const { model, effort } = this.purposeRoute(purpose, arm);
    return { kind: 'claude', purpose, model, effort, arm, untagged: scope === undefined };
  }

  upstreamKeyFor(role: InferenceModelRole): string | undefined {
    const route = this.resolve(role, inferencePurposeScope.current());
    if (route.kind !== 'claude' || !this.#config.identity.models.includes(route.model)) {
      return undefined;
    }
    return `${UPSTREAM_KEY_PREFIX}${route.model}`;
  }

  expectedIdentity(): {
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
  } {
    const { organizationIdSha256, workspaceIdSha256 } = this.#config.identity;
    return { organizationIdSha256, workspaceIdSha256 };
  }

  allowedModels(): readonly ClaudeModelId[] {
    return [...this.#config.identity.models];
  }

  callGraph(arm: ClaudeArmId): ClaudeCallGraph {
    return arm === DEFAULT_ARM ? this.#config.callGraph : this.#config.arms[arm].callGraph;
  }

  shadowArmsFor(orgId: string, requested: readonly ShadowArm[]): ShadowArm[] {
    const { shadowOrgIdSha256 } = this.#config;
    if (shadowOrgIdSha256 === '' || sha256Hex(orgId) !== shadowOrgIdSha256) return [];
    return [...new Set(requested)].filter((arm) => arm in this.#config.arms);
  }

  reviewSamplePercent(): number {
    return this.#config.reviewSamplePercent;
  }

  private purposeRoute(
    purpose: ClaudeInferencePurpose,
    arm: ClaudeArmId,
  ): { readonly model: ClaudeModelId; readonly effort: ClaudeEffort } {
    const armRoute = arm === DEFAULT_ARM ? undefined : this.#config.arms[arm].purposes[purpose];
    return armRoute ?? this.#config.purposes[purpose];
  }
}
