import type { TitleDigestPort } from '@folklore/api';
import { TenantKeyedHasher } from '../sealing/TenantKeyedHasher.js';
import { TenantContextZeroizedError } from '../tenant/tenant-context.js';
import type { ResolveTenant } from '../tenant/tenant-resolver.js';

const DIGEST_DOMAIN = 'folklore:title-digest:v1\0';

export class EnclaveTitleDigester implements TitleDigestPort {
  constructor(private readonly resolveTenant: ResolveTenant) {}

  digest(ref: { orgId: string; pageId: string }, title: string): string {
    const tenant = this.resolveTenant(ref.orgId);
    const key = tenant.titleDigestKey();
    if (!key) throw new TenantContextZeroizedError(tenant.tenantId);
    const hasher = new TenantKeyedHasher(
      key,
      () => new TenantContextZeroizedError(tenant.tenantId),
    );
    try {
      return hasher
        .begin(DIGEST_DOMAIN)
        .update(JSON.stringify([ref.orgId, ref.pageId, title]))
        .digest('hex');
    } finally {
      hasher.zeroize();
    }
  }
}
