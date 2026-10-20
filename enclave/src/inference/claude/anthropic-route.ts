import { CLAUDE_ROUTE_MODEL_IDS, type ClaudeModelId } from '@folklore/contracts';
import type { ProviderRoute } from '../routing/InferenceRouteResolver.js';

export type AnthropicRoute = ProviderRoute & {
  readonly provider: 'anthropic';
  readonly model: ClaudeModelId;
};

export function isClaudeModelId(model: string): model is ClaudeModelId {
  return (CLAUDE_ROUTE_MODEL_IDS as readonly string[]).includes(model);
}

// The resolver accepts only Claude models for a compiled anthropic target, so the provider alone narrows the model.
export function isAnthropicRoute(route: ProviderRoute): route is AnthropicRoute {
  return route.provider === 'anthropic';
}
