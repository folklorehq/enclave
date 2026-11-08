interface RecordedConsent {
  readonly revision: number;
  readonly allowed: boolean;
}

// UNWIRED: nothing calls allows() until the Batch route reads consent.
/** Batch consent from the last applied attested projection, RAM only; unknown or false means synchronous. */
export class TenantBatchConsent {
  private readonly byOrg = new Map<string, RecordedConsent>();

  record(orgId: string, revision: number, allowed: boolean | undefined): void {
    const held = this.byOrg.get(orgId);
    if (held && revision < held.revision) return;
    this.byOrg.set(orgId, { revision, allowed: allowed === true });
  }

  allows(orgId: string): boolean {
    return this.byOrg.get(orgId)?.allowed === true;
  }
}
