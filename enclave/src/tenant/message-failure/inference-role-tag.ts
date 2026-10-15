import { inferenceModelRoleSchema, type InferenceModelRole } from '@folklore/contracts';

const INFERENCE_ROLES: ReadonlySet<string> = new Set(inferenceModelRoleSchema.options);
// Module-private, so a role reaches a failure code only through `tagInferenceRole`.
const ROLE_BY_ERROR = new WeakMap<object, InferenceModelRole>();

/** Records the closed inference role an error failed under; the first role recorded stays. */
export function tagInferenceRole(error: unknown, role: InferenceModelRole): void {
  if (typeof error !== 'object' || error === null || !INFERENCE_ROLES.has(role)) return;
  if (!ROLE_BY_ERROR.has(error)) ROLE_BY_ERROR.set(error, role);
}

export function inferenceRoleOf(error: unknown): InferenceModelRole | undefined {
  return typeof error === 'object' && error !== null ? ROLE_BY_ERROR.get(error) : undefined;
}
