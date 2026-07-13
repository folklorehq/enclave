// Content-free (ADL #18): carries only a tenant count, never an id or customer data.
export class SharedTierReadPathError extends Error {
  constructor(readonly tenantCount: number) {
    super(
      `shared-tier read path not yet supported (N=${tenantCount}); per-request resolver pending §4.2`,
    );
    this.name = 'SharedTierReadPathError';
  }
}

// The in-enclave read/synthesis path is still single-context, so a shared pool (N>1) must refuse it
// rather than serve a non-primary tenant's read from the primary context — fail loud at boot, not
// opaquely at request time. Per-request keyring selection from the JWT orgId is the follow-up (§4.2).
export function assertReadPathSupported(tenantCount: number): void {
  if (tenantCount > 1) throw new SharedTierReadPathError(tenantCount);
}
