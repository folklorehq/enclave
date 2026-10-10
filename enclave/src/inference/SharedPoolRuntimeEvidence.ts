import type { VerifiedActivePolicySnapshotV1 } from '@folklore/inference';
import type { BootSessionState, RuntimeEvidenceSessionPort } from '../attestation/ports.js';
import type { BootBoundGenerationContext } from './BootStateActivePolicyReferenceVerifier.js';
import {
  expectedTenantGenerationContext,
  type AssignedTenantDeployment,
} from './expected-tenant-generation-context.js';
import { assertGenerationContextEqual } from './renewal-grace.js';
import type { TenantPolicyRuntimeEvidencePort } from './TenantPolicyBoundInference.js';

export const sharedPoolRuntimeEvidenceErrors = {
  tenantMismatch: 'runtime_evidence_tenant_mismatch',
  snapshotNotInstalled: 'runtime_evidence_snapshot_not_installed',
  providerPolicyUnavailable: 'runtime_evidence_provider_policy_unavailable',
  attestationUnavailable: 'runtime_evidence_attestation_unavailable',
  bootUnverified: 'runtime_evidence_boot_unverified',
  sessionInvalid: 'runtime_evidence_session_invalid',
  generationContextMismatch: 'runtime_evidence_generation_context_mismatch',
} as const;

export interface SharedPoolRuntimeEvidenceDeps {
  readonly tenantId: string;
  readonly installedSnapshot: () => VerifiedActivePolicySnapshotV1 | undefined;
  readonly providerPolicyInstalled: () => boolean;
  readonly attestation: () => RuntimeEvidenceSessionPort | null | undefined;
  readonly assignedTenant: () => AssignedTenantDeployment | undefined;
  readonly bootContext: () => BootBoundGenerationContext | undefined;
}

const SESSION_ID_PATTERN = /^[0-9a-f]{64}$/;

/** Refuses an operation unless its snapshot is the tenant's installed one on a verified, unsealed boot. */
export class SharedPoolRuntimeEvidence implements TenantPolicyRuntimeEvidencePort {
  constructor(private readonly deps: SharedPoolRuntimeEvidenceDeps) {}

  assertSnapshot(snapshot: VerifiedActivePolicySnapshotV1): void {
    if (snapshot.orgId !== this.deps.tenantId || snapshot.tenantId !== this.deps.tenantId) {
      throw new Error(sharedPoolRuntimeEvidenceErrors.tenantMismatch);
    }
    if (this.deps.installedSnapshot() !== snapshot) {
      throw new Error(sharedPoolRuntimeEvidenceErrors.snapshotNotInstalled);
    }
    if (!this.deps.providerPolicyInstalled()) {
      throw new Error(sharedPoolRuntimeEvidenceErrors.providerPolicyUnavailable);
    }
    this.assertSession(this.bootSession());
    this.assertGenerationContext(snapshot);
  }

  private bootSession(): BootSessionState {
    const attestation = this.deps.attestation();
    if (!attestation) throw new Error(sharedPoolRuntimeEvidenceErrors.attestationUnavailable);
    try {
      return attestation.runtimeEvidenceSession();
    } catch {
      throw new Error(sharedPoolRuntimeEvidenceErrors.bootUnverified);
    }
  }

  private assertSession(session: BootSessionState): void {
    if (
      !SESSION_ID_PATTERN.test(session.sessionId) ||
      !Number.isSafeInteger(session.bootEpoch) ||
      session.bootEpoch < 1
    ) {
      throw new Error(sharedPoolRuntimeEvidenceErrors.sessionInvalid);
    }
  }

  private assertGenerationContext(snapshot: VerifiedActivePolicySnapshotV1): void {
    try {
      const expected = expectedTenantGenerationContext({
        tenantId: this.deps.tenantId,
        snapshot,
        tenant: this.deps.assignedTenant(),
        boot: this.deps.bootContext(),
      });
      assertGenerationContextEqual(snapshot.generationContext, expected);
    } catch {
      throw new Error(sharedPoolRuntimeEvidenceErrors.generationContextMismatch);
    }
  }
}
