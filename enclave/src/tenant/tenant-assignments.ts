// One assigned tenant's content-free routing identifiers (design §4.3). All fields are ids/URLs,
// never customer data. Stage 2 reads the set from env; when the control plane's assignment manifest
// lands (Stage 5) this shape moves to @folklore/contracts as the delivered wire DTO.
export interface TenantAssignment {
  tenantId: string;
  kmsKeyId: string;
  queueUrl: string;
  recoveryPubkey: string;
}

const REQUIRED_FIELDS = ['tenantId', 'kmsKeyId', 'queueUrl'] as const;

// Resolves the enclave's assigned tenants. A dedicated box (the default tier, design §6.1) is the
// single-tenant fallback — TENANT_ID/KMS_KEY_ID/QUEUE_URL — so N=1 stays a first-class path. A
// shared-pool host instead gets TENANT_ASSIGNMENTS (a JSON array), yielding N contexts.
export function parseTenantAssignments(env: NodeJS.ProcessEnv): TenantAssignment[] {
  const manifest = env['TENANT_ASSIGNMENTS']?.trim();
  const assignments = manifest ? parseManifest(manifest) : parseSingleTenant(env);

  if (assignments.length === 0) {
    throw new Error('no tenant assignments configured (set TENANT_ASSIGNMENTS or TENANT_ID)');
  }
  assertNoDuplicates(assignments);
  return assignments;
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
  return {
    tenantId: (record['tenantId'] as string).trim(),
    kmsKeyId: (record['kmsKeyId'] as string).trim(),
    queueUrl: (record['queueUrl'] as string).trim(),
    recoveryPubkey: typeof record['recoveryPubkey'] === 'string' ? record['recoveryPubkey'] : '',
  };
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
