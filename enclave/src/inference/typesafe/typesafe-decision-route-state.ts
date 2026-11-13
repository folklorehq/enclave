import {
  INFERENCE_MODEL_CATALOG,
  JEV_DECISION_MODEL_ID,
  type InferenceModelId,
} from '@folklore/contracts';
import {
  TYPESAFE_DECISION_ROUTE_IDENTITY,
  TYPESAFE_PROVIDER,
  type TypeSafeDecisionRouteIdentity,
} from './typesafe-decision-route-config.js';

export type TypeSafeDecisionRouteInvalidReason =
  | 'key_binding_malformed'
  | 'org_hash_malformed'
  | 'org_scope_empty'
  | 'model_not_typesafe';

export type TypeSafeDecisionRouteState =
  | { readonly kind: 'disabled' }
  | {
      readonly kind: 'enabled';
      readonly identity: TypeSafeDecisionRouteIdentity;
      readonly model: InferenceModelId;
    }
  | { readonly kind: 'invalid'; readonly reason: TypeSafeDecisionRouteInvalidReason };

export const TYPESAFE_DECISION_ROUTE_INVALID_ALARM = 'typesafe_decision_route_invalid';

const SHA256_HEX = /^[0-9a-f]{64}$/;

function invalidReason(
  identity: TypeSafeDecisionRouteIdentity,
  model: InferenceModelId,
): TypeSafeDecisionRouteInvalidReason | undefined {
  if (!SHA256_HEX.test(identity.apiKeyBinding)) return 'key_binding_malformed';
  if (!identity.orgIdSha256s.every((hash) => SHA256_HEX.test(hash))) return 'org_hash_malformed';
  if (identity.orgScope === 'own_org' && identity.orgIdSha256s.length === 0) {
    return 'org_scope_empty';
  }
  return INFERENCE_MODEL_CATALOG[model].provider === TYPESAFE_PROVIDER
    ? undefined
    : 'model_not_typesafe';
}

/** Pure and total: a malformed literal becomes `invalid`, never an import-time throw. */
export function typesafeDecisionRouteState(
  identity: TypeSafeDecisionRouteIdentity,
  model: InferenceModelId,
): TypeSafeDecisionRouteState {
  if (!identity.enabled) return { kind: 'disabled' };
  const reason = invalidReason(identity, model);
  return reason === undefined ? { kind: 'enabled', identity, model } : { kind: 'invalid', reason };
}

export const TYPESAFE_DECISION_ROUTE_STATE: TypeSafeDecisionRouteState = typesafeDecisionRouteState(
  TYPESAFE_DECISION_ROUTE_IDENTITY,
  JEV_DECISION_MODEL_ID,
);
