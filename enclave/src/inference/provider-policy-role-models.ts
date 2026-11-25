import {
  inferenceTrustPolicyV2Schema,
  type InferenceModelRole,
  type InferenceTrustPolicyV2,
} from '@folklore/contracts';

const TEST_ROLE_MODELS: Record<InferenceModelRole, { model: string; revision: string }> = {
  embed: { model: 'qwen/qwen3-embedding-8b', revision: 'test' },
  generate: { model: 'z-ai/glm-5.2', revision: 'test' },
  judge: { model: 'qwen/qwen3-32b', revision: 'test' },
  critique: { model: 'qwen/qwen3-32b', revision: 'test' },
};

let installed: InferenceTrustPolicyV2 | undefined;

/** Installs the signed provider policy whose role models every active-policy role binding must name. */
export function setProviderInferenceTrustPolicy(policy: unknown): void {
  const parsed = inferenceTrustPolicyV2Schema.parse(policy);
  if (parsed.evidence.profile !== 'dstack-tdx-public-v1') {
    throw new Error('public inference trust policy requires dstack-tdx-public-v1 profile');
  }
  if (installed) {
    if (JSON.stringify(installed) !== JSON.stringify(parsed)) {
      throw new Error('public inference trust policy changed');
    }
    return;
  }
  installed = parsed;
}

export function policyRoleModel(role: InferenceModelRole): string {
  return roleModel(role).model;
}

export function policyRoleModelRevision(role: InferenceModelRole): string {
  return roleModel(role).revision;
}

function roleModel(role: InferenceModelRole): { model: string; revision: string } {
  if (installed) return installed.roleModels[role];
  if (process.env['NODE_ENV'] === 'test') return TEST_ROLE_MODELS[role];
  throw new Error('inference commissioning prerequisite unmet: signed trust policy unavailable');
}
