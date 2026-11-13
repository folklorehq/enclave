export const TYPESAFE_PROVIDER = 'typesafe';

export interface TypeSafeDecisionRouteIdentity {
  readonly enabled: boolean;
  readonly apiKeyBinding: string;
  readonly orgScope: 'own_org' | 'all_orgs';
  readonly orgIdSha256s: readonly string[];
}

// Domain-separates the stored key binding from any other digest of the same key.
export const TYPESAFE_KEY_BINDING_DOMAIN = 'folklore.typesafe-api-key-binding.v1';

// prettier-ignore
export const TYPESAFE_DECISION_ROUTE_IDENTITY: TypeSafeDecisionRouteIdentity = {"enabled":false,"apiKeyBinding":"","orgScope":"own_org","orgIdSha256s":[]};
