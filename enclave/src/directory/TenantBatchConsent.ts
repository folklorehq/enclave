interface RecordedConsent {
  readonly revision: number;
  readonly allowed: boolean;
}

// UNWIRED: allows() is read only by the Batch route, which stays off while its compiled flag is false.
/** Batch consent from the last applied attested projection, RAM only; unknown or false means synchronous. */
export class TenantBatchConsent {
  private readonly byOrg = new Map<string, RecordedConsent>();

  record(orgId: string, revision: number, allowed: boolean | undefined): void {
    const held = this.byOrg.get(orgId);
    if (held && revision < held.revision) return;
    this.byOrg.set(orgId, { revision, allowed: allowed === true });
  }

  decision(orgId: string): boolean | undefined {
    return this.byOrg.get(orgId)?.allowed;
  }

  allows(orgId: string): boolean {
    return this.byOrg.get(orgId)?.allowed === true;
  }
}
