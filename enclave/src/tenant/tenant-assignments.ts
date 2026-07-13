import {
  type AssignmentManifest,
  type TenantAssignment,
  parseAssignmentManifest as parseContractManifest,
  tenantAssignmentSchema,
} from '@folklore/contracts';

// The assignment shape is defined ONCE in @folklore/contracts (design §4.3) so the control-plane
// producer and this consumer cannot drift. Env parsing is the bootstrap/dedicated fallback (§6.1);
// `parseAssignmentManifest` is the runtime path for a manifest delivered on the check-in channel.
export type { TenantAssignment, AssignmentManifest };

const REQUIRED_FIELDS = ['tenantId', 'kmsKeyId', 'queueUrl'] as const;

/** Resolves the enclave's assigned tenants from env: TENANT_ASSIGNMENTS (a JSON array, shared pool) or the TENANT_ID single-tenant fallback (a dedicated box, the default tier §6.1). */
export function parseTenantAssignments(env: NodeJS.ProcessEnv): TenantAssignment[] {
  const manifest = env['TENANT_ASSIGNMENTS']?.trim();
  const assignments = manifest ? parseManifest(manifest) : parseSingleTenant(env);

  if (assignments.length === 0) {
    throw new Error('no tenant assignments configured (set TENANT_ASSIGNMENTS or TENANT_ID)');
  }
  assertNoDuplicates(assignments);
  return assignments;
}

/** Validates a check-in-delivered assignment manifest (design §4.3) via the shared routing guard, then enforces the registry's no-duplicate-tenant invariant. */
export function parseAssignmentManifest(
  manifest: unknown,
  expectedPoolId: string,
): TenantAssignment[] {
  const parsed = parseContractManifest(manifest, expectedPoolId);
  assertNoDuplicates(parsed.assignments);
  return parsed.assignments;
}

function parseManifest(manifest: string): TenantAssignment[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(manifest);
  } catch {
    throw new Error('TENANT_ASSIGNMENTS is not valid JSON');
  }
  if (!Array.isArray(parsed)) throw new Error('TENANT_ASSIGNMENTS must be a JSON array');
  return parsed.map((entry, index) => toAssignment(entry, index));
}

function parseSingleTenant(env: NodeJS.ProcessEnv): TenantAssignment[] {
  const tenantId = env['TENANT_ID']?.trim();
  if (!tenantId) return [];
  return [
    toAssignment(
      {
        tenantId,
        kmsKeyId: env['KMS_KEY_ID'],
        queueUrl: env['QUEUE_URL'],
        recoveryPubkey: env['RECOVERY_PUBKEY'] ?? '',
      },
      0,
    ),
  ];
}

// Friendly per-field messages first (a misconfigured env should name the missing field), then the
// shared zod schema is the authoritative shape guard — the returned value is a contract-valid
// TenantAssignment, never a locally-shaped near-miss.
function toAssignment(entry: unknown, index: number): TenantAssignment {
  if (typeof entry !== 'object' || entry === null) {
    throw new Error(`tenant assignment [${index}] is not an object`);
  }
  const record = entry as Record<string, unknown>;
  for (const field of REQUIRED_FIELDS) {
    const value = record[field];
    if (typeof value !== 'string' || value.trim() === '') {
      throw new Error(`tenant assignment [${index}] is missing ${field}`);
    }
  }
  return tenantAssignmentSchema.parse({
    tenantId: (record['tenantId'] as string).trim(),
    kmsKeyId: (record['kmsKeyId'] as string).trim(),
    queueUrl: (record['queueUrl'] as string).trim(),
    recoveryPubkey: typeof record['recoveryPubkey'] === 'string' ? record['recoveryPubkey'] : '',
  });
}

function assertNoDuplicates(assignments: TenantAssignment[]): void {
  const seen = new Set<string>();
  for (const assignment of assignments) {
    if (seen.has(assignment.tenantId)) {
      throw new Error(`duplicate tenant assignment for ${assignment.tenantId}`);
    }
    seen.add(assignment.tenantId);
  }
}
