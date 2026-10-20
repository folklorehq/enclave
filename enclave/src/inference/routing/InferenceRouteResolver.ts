import { createHash } from 'node:crypto';
import {
  CLAUDE_ROUTE_MODEL_IDS,
  COMPILED_DEFAULT_ROUTING,
  INFERENCE_MODEL_CATALOG,
  INFERENCE_PURPOSES,
  inferenceTimeoutMs,
  inferencePurposeNeverFallsBack,
  mergedPurposeRoutes,
  routingTableBodyRefusal,
  type ClaudeModelId,
  type CompiledRouting,
  type InferenceArmId,
  type InferenceEffort,
  type InferenceModelCatalogEntry,
  type InferenceModelId,
  type InferenceModelRole,
  type InferencePurpose,
  type PurposeRoute,
  type RoutedProviderId,
  type RouteTarget,
  type ShadowArm,
} from '@folklore/contracts';
import { isAnthropicRoute, isClaudeModelId } from '../claude/anthropic-route.js';
import {
  CLAUDE_ROUTE_CONFIG,
  type ClaudeCallGraph,
  type ClaudeRouteConfig,
} from '../claude/claude-route-config.js';
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
import { routingSnapshotScope, type RoutingSnapshot } from './routing-snapshot-scope.js';
import type { RoutingTableSource } from './RoutingTableRefresher.js';

export type InferenceRoute =
  | { readonly kind: 'aci' }
  | {
      readonly kind: 'provider';
      readonly provider: RoutedProviderId;
      readonly purpose: InferencePurpose;
      readonly model: InferenceModelId;
      readonly effort: InferenceEffort;
      readonly arm: InferenceArmId;
      readonly untagged: boolean;
    };

export type ProviderRoute = Extract<InferenceRoute, { kind: 'provider' }>;

export const ACI_ROUTE: InferenceRoute = Object.freeze({ kind: 'aci' });

const SHA256_HEX = /^[0-9a-f]{64}$/;
const ARM_IDS: readonly string[] = ['B', 'R'];
const PHALA_PROVIDER = 'phala';
const ROUTE_FALLBACK_ALARM = 'inference_route_fallback';
const VALIDATION_ISSUED_AT_MS = 1_000_000;
const MS_PER_SECOND = 1000;
const COMPILED_ROUTABLE_PROVIDERS = new Set<RouteTarget['provider']>(['anthropic']);

const DEFAULT_PURPOSE_BY_ROLE: Readonly<
  Record<Exclude<InferenceModelRole, 'embed'>, InferencePurpose>
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

export function assertClaudeRouteConfig(config: ClaudeRouteConfig, routing: CompiledRouting): void {
  assertIdentity(config.identity);
  assertArms(config);
  assertModelsAndTimeouts(config, routing);
  assertCompiledRouting(routing);
}

function disabledCopy(config: ClaudeRouteConfig): ClaudeRouteConfig {
  return { ...config, identity: { ...config.identity, enabled: false } };
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export class InferenceRouteResolver {
  readonly #tables: RoutingTableSource;
  readonly #config: ClaudeRouteConfig;
  readonly #routing: CompiledRouting;
  readonly #invalidReason: string | undefined;

  constructor(
    tables: RoutingTableSource,
    config: ClaudeRouteConfig = CLAUDE_ROUTE_CONFIG,
    routing: CompiledRouting = COMPILED_DEFAULT_ROUTING,
  ) {
    this.#tables = tables;
    this.#routing = routing;
    try {
      assertClaudeRouteConfig(config, routing);
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

  snapshotFor(orgId: string): RoutingSnapshot {
    const table = this.enabled ? this.#tables.current()?.table : undefined;
    return {
      orgId,
      version: table?.version ?? 0,
      purposes: mergedPurposeRoutes(table, sha256Hex(orgId), this.#routing),
    };
  }

  resolve(
    role: InferenceModelRole,
    scope: InferencePurposeContext | undefined,
    orgId: string,
  ): InferenceRoute {
    return this.routeChain(role, scope, orgId)[0] ?? ACI_ROUTE;
  }

  routeChain(
    role: InferenceModelRole,
    scope: InferencePurposeContext | undefined,
    orgId: string,
  ): readonly InferenceRoute[] {
    if (role === 'embed' || !this.enabled) return [ACI_ROUTE];
    const purpose = scope?.purpose ?? DEFAULT_PURPOSE_BY_ROLE[role];
    const arm = scope?.arm ?? DEFAULT_ARM;
    const untagged = scope === undefined;
    const targets = this.targetsFor(purpose, arm, orgId);
    const routes = targets.map((target) =>
      InferenceRouteResolver.routeFor(target, purpose, arm, untagged),
    );
    return InferenceRouteResolver.withoutRepeatedAci(routes);
  }

  upstreamKeyFor(role: InferenceModelRole, orgId: string): string | undefined {
    return this.upstreamKeyOfRoute(this.resolve(role, inferencePurposeScope.current(), orgId));
  }

  upstreamKeyOfRoute(route: InferenceRoute): string | undefined {
    if (route.kind !== 'provider') return undefined;
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

  callGraph(arm: InferenceArmId): ClaudeCallGraph {
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

  noteFallback(): void {
    if (this.enabled) this.#tables.alarm(ROUTE_FALLBACK_ALARM);
  }

  private static withoutRepeatedAci(routes: readonly InferenceRoute[]): readonly InferenceRoute[] {
    const firstAci = routes.findIndex((route) => route.kind === 'aci');
    return routes.filter((route, index) => route.kind !== 'aci' || index === firstAci);
  }

  private targetsFor(
    purpose: InferencePurpose,
    arm: InferenceArmId,
    orgId: string,
  ): readonly RouteTarget[] {
    if (arm !== DEFAULT_ARM) return [this.armTarget(purpose, arm)];
    const snapshot = routingSnapshotScope.current();
    const purposes =
      snapshot?.orgId === orgId ? snapshot.purposes : this.snapshotFor(orgId).purposes;
    const route: PurposeRoute = purposes[purpose];
    return inferencePurposeNeverFallsBack(purpose) ? [route] : [route, ...route.fallbacks];
  }

  private armTarget(purpose: InferencePurpose, arm: Exclude<InferenceArmId, 'D'>): RouteTarget {
    const armRoute = this.#config.arms[arm].purposes[purpose];
    if (armRoute !== undefined) return { provider: 'anthropic', ...armRoute };
    return this.#routing.purposes[purpose];
  }

  private static routeFor(
    target: RouteTarget,
    purpose: InferencePurpose,
    arm: InferenceArmId,
    untagged: boolean,
  ): InferenceRoute {
    if (target.provider === PHALA_PROVIDER) return ACI_ROUTE;
    return {
      kind: 'provider',
      provider: target.provider,
      purpose,
      model: target.model as InferenceModelId,
      effort: target.effort,
      arm,
      untagged,
    };
  }
}
