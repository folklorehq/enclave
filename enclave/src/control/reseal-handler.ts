import { type Command, Ed25519CommandAuthorizer } from '@folklore/control-plane';
import { resealForSharedParamsSchema } from '@folklore/contracts';
import { resealMasterKey, type ResealDeps } from '../sealing/reseal.js';

export interface ResealForSharedHandlerDeps {
  authorizer: Ed25519CommandAuthorizer;
  reseal: ResealDeps;
  // Fail-closed: an org not assigned to this enclave resolves to undefined and is rejected before any key material is touched.
  resolveTenantCmk: (tenantId: string) => string | undefined;
}

// Re-verifies the deployment-bound Ed25519 quorum (ADL #13/#61) before re-sealing, so a quorum signed for another box or with swapped params cannot re-bind this tenant's key.
// Not yet wired into an enclave command-dispatch path — no live caller reaches it.
export class ResealForSharedHandler {
  constructor(private readonly deps: ResealForSharedHandlerDeps) {}

  async handle(command: Command): Promise<{ resealed: true }> {
    if (command.action !== 'reseal_for_shared') {
      throw new Error('reseal-for-shared: unexpected command action');
    }
    if (!(await this.deps.authorizer.authorize(command))) {
      throw new Error('reseal-for-shared: quorum re-verification failed');
    }
    const params = resealForSharedParamsSchema.parse(command.params);
    const kmsKeyId = this.deps.resolveTenantCmk(params.tenantId);
    if (!kmsKeyId) throw new Error('reseal-for-shared: tenant not assigned to this enclave');

    // ADL #61: the per-tenant CMK is unchanged; re-seal under the same key + tenant AAD so a pool
    // enclave (same PCR0) can unseal it. The pool-role KMS grant is an infra op outside the enclave.
    await resealMasterKey(this.deps.reseal, {
      tenantId: params.tenantId,
      sourceKmsKeyId: kmsKeyId,
      targetKmsKeyId: kmsKeyId,
    });
    return { resealed: true };
  }
}
