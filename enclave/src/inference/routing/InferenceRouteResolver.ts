import {
  CLAUDE_ROUTE_MODEL_IDS,
  COMPILED_DEFAULT_ROUTING,
  INFERENCE_MODEL_CATALOG,
  INFERENCE_PURPOSES,
  inferenceTimeoutMs,
  routingTableBodyRefusal,
  type ClaudeModelId,
  type CompiledRouteTarget,
  type CompiledRouting,
  type InferenceArmId,
  type InferenceEffort,
  type InferenceModelCatalogEntry,
  type InferenceModelId,
  type InferenceModelRole,
  type InferencePurpose,
  type RoutedProviderId,
  type RouteTarget,
} from '@folklore/contracts';
import { isAnthropicRoute, isClaudeModelId } from '../claude/anthropic-route.js';
import { CLAUDE_ROUTE_CONFIG, type ClaudeRouteConfig } from '../claude/claude-route-config.js';
import {
  CLAUDE_ROUTE_CONFIG_INVALID,
  ClaudeRouteConfigError,
} from '../claude/claude-route-errors.js';
import {
  DEFAULT_ARM,
  inferencePurposeScope,
  type InferencePurposeContext,
} from '../InferencePurposeScope.js';
import { PROVIDER_ROUTE_POLICY } from './provider-route-policy.js';

export interface InferenceRoute {
  readonly kind: 'provider';
  readonly provider: RoutedProviderId;
  readonly purpose: InferencePurpose;
  readonly model: InferenceModelId;
  readonly effort: InferenceEffort;
  readonly arm: InferenceArmId;
  readonly untagged: boolean;
}

export type ProviderRoute = InferenceRoute;

/** Every role but embed: embeddings take the compiled OpenAI route, not this table. */
export type GenerativeRole = Exclude<InferenceModelRole, 'embed'>;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const ARM_IDS: readonly string[] = ['B', 'R'];
const VALIDATION_ISSUED_AT_MS = 1_000_000;
const MS_PER_SECOND = 1000;
const COMPILED_ROUTABLE_PROVIDERS = new Set<RouteTarget['provider']>(['anthropic']);

const DEFAULT_PURPOSE_BY_ROLE: Readonly<Record<GenerativeRole, InferencePurpose>> = {
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

function assertCompiledRouting(routing: CompiledRouting): void {
  const purposes = Object.fromEntries(
    INFERENCE_PURPOSES.map((purpose) => [purpose, { ...routing.purposes[purpose], fallbacks: [] }]),
  );
  const refusal = routingTableBodyRefusal(
    {
      version: VALIDATION_ISSUED_AT_MS / MS_PER_SECOND,
      issuedAtMs: VALIDATION_ISSUED_AT_MS,
      notAfterMs: VALIDATION_ISSUED_AT_MS + 1,
      purposes,
      orgOverrides: [],
    },
    {
      nowMs: VALIDATION_ISSUED_AT_MS,
      highWaterVersion: 0,
      routableProviders: COMPILED_ROUTABLE_PROVIDERS,
    },
  );
  if (refusal !== undefined) invalid(refusal);
}

function assertPairResolvable(
  identity: ClaudeRouteConfig['identity'],
  purpose: InferencePurpose,
  model: string,
): void {
  if (!isClaudeModelId(model) || !identity.models.includes(model)) invalid('model_not_allowed');
  const entry: InferenceModelCatalogEntry = INFERENCE_MODEL_CATALOG[model];
  if (inferenceTimeoutMs(entry, purpose) === undefined) {
    invalid('routing_table_purpose_class_unsupported');
  }
}

function assertModelsAndTimeouts(config: ClaudeRouteConfig, routing: CompiledRouting): void {
  const { identity } = config;
  if (!identity.models.every((model) => CLAUDE_ROUTE_MODEL_IDS.includes(model))) {
    invalid('model_not_in_allowlist');
  }
  for (const purpose of INFERENCE_PURPOSES) {
    assertPairResolvable(identity, purpose, routing.purposes[purpose].model);
  }
  for (const arm of Object.values(config.arms)) {
    for (const [purpose, route] of Object.entries(arm.purposes)) {
      assertPairResolvable(identity, purpose as InferencePurpose, route.model);
    }
  }
}

function assertArms(config: ClaudeRouteConfig): void {
  if (Object.keys(config.arms).sort().join() !== ARM_IDS.join()) invalid('arms_invalid');
  const known = new Set<string>(INFERENCE_PURPOSES);
  for (const arm of Object.values(config.arms)) {
    if (!Object.keys(arm.purposes).every((purpose) => known.has(purpose))) invalid('arm_purpose');
  }
}

function assertClaudeRouteConfig(config: ClaudeRouteConfig, routing: CompiledRouting): void {
  assertIdentity(config.identity);
  assertArms(config);
  assertModelsAndTimeouts(config, routing);
  assertCompiledRouting(routing);
}

function disabledCopy(config: ClaudeRouteConfig): ClaudeRouteConfig {
  return {
    ...config,
    identity: { ...config.identity, enabled: false },
  };
}

export class InferenceRouteResolver {
  readonly #config: ClaudeRouteConfig;
  readonly #routing: CompiledRouting;
  readonly #invalidReason: string | undefined;
  readonly #invalidRule: string | undefined;

  constructor(
    config: ClaudeRouteConfig = CLAUDE_ROUTE_CONFIG,
    routing: CompiledRouting = COMPILED_DEFAULT_ROUTING,
  ) {
    this.#routing = routing;
    try {
      assertClaudeRouteConfig(config, routing);
      this.#config = config;
      this.#invalidReason = undefined;
      this.#invalidRule = undefined;
    } catch (error) {
      this.#config = disabledCopy(config);
      this.#invalidReason = error instanceof Error ? error.message : CLAUDE_ROUTE_CONFIG_INVALID;
      this.#invalidRule = error instanceof ClaudeRouteConfigError ? error.rule : 'unknown';
    }
  }

  get enabled(): boolean {
    return this.#config.identity.enabled && this.#invalidReason === undefined;
  }

  get invalidReason(): string | undefined {
    return this.#invalidReason;
  }

  // Routing is the same for every org; the page pipeline still passes its org id.
  // A disabled or invalid route refuses the call: there is no other generation route to fall back to.
  resolve(
    role: GenerativeRole,
    scope: InferencePurposeContext | undefined,
    _orgId?: string,
  ): InferenceRoute {
    if (!this.enabled) throw new ClaudeRouteConfigError(this.#invalidRule ?? 'route_disabled');
    const purpose = scope?.purpose ?? DEFAULT_PURPOSE_BY_ROLE[role];
    const arm = scope?.arm ?? DEFAULT_ARM;
    const target =
      arm === DEFAULT_ARM ? this.#routing.purposes[purpose] : this.armTarget(purpose, arm);
    return {
      kind: 'provider',
      provider: target.provider,
      purpose,
      model: target.model,
      effort: target.effort,
      arm,
      untagged: scope === undefined,
    };
  }

  upstreamKeyFor(role: GenerativeRole): string | undefined {
    if (!this.enabled) return undefined;
    return this.upstreamKeyOfRoute(this.resolve(role, inferencePurposeScope.current()));
  }

  upstreamKeyOfRoute(route: InferenceRoute): string | undefined {
    if (isAnthropicRoute(route) && !this.#config.identity.models.includes(route.model)) {
      return undefined;
    }
    return `${PROVIDER_ROUTE_POLICY[route.provider].upstreamKeyPrefix}${route.model}`;
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

  reviewSamplePercent(): number {
    return this.#config.reviewSamplePercent;
  }

  private armTarget(
    purpose: InferencePurpose,
    arm: Exclude<InferenceArmId, 'D'>,
  ): CompiledRouteTarget {
    const armRoute = this.#config.arms[arm].purposes[purpose];
    if (armRoute !== undefined) return { provider: 'anthropic', ...armRoute };
    return this.#routing.purposes[purpose];
  }
}
