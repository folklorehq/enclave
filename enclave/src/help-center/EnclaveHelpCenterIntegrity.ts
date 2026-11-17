// UNWIRED: no composition root builds this yet.
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { HelpCenterIntegrity, HelpCenterMacTable } from '@folklore/api';
import { canonicalJson } from '@folklore/utils';
import type { TenantContext } from '../tenant/tenant-context.js';
import { requireActivatedTenant, resolveActivatedTenant } from './activated-tenant.js';
import type { HelpCenterAdapterDeps } from './ports.js';

const INTEGRITY_KEY_UNAVAILABLE = 'help_center_integrity_key_unavailable';
const MAC_FIELDS_INVALID = 'help_center_mac_fields_invalid';
const MAC_HEX = /^[0-9a-f]{64}$/;

export class EnclaveHelpCenterIntegrity implements HelpCenterIntegrity {
  constructor(private readonly deps: HelpCenterAdapterDeps) {}

  mac(orgId: string, table: HelpCenterMacTable, fields: Readonly<Record<string, unknown>>): string {
    const tenant = this.activatedTenant(orgId);
    const message = this.macMessage(orgId, table, fields);
    return this.hmacHex(tenant.helpCenterIntegrityKey(), message);
  }

  verify(
    orgId: string,
    table: HelpCenterMacTable,
    fields: Readonly<Record<string, unknown>>,
    mac: string,
  ): boolean {
    const resolved = resolveActivatedTenant(this.deps, orgId, INTEGRITY_KEY_UNAVAILABLE);
    if (resolved === null || !MAC_HEX.test(mac)) return false;
    const message = this.messageOrNull(orgId, table, fields);
    if (message === null) return false;
    const expected = this.hmacHex(resolved.tenant.helpCenterIntegrityKey(), message);
    return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(mac, 'hex'));
  }

  slugDigest(orgId: string, slug: string): string {
    return this.hmacHex(this.activatedTenant(orgId).helpCenterSlugKey(), slug);
  }

  private activatedTenant(orgId: string): TenantContext {
    return requireActivatedTenant(this.deps, orgId, INTEGRITY_KEY_UNAVAILABLE).tenant;
  }

  private messageOrNull(
    orgId: string,
    table: HelpCenterMacTable,
    fields: Readonly<Record<string, unknown>>,
  ): string | null {
    try {
      return this.macMessage(orgId, table, fields);
    } catch {
      return null;
    }
  }

  private macMessage(
    orgId: string,
    table: HelpCenterMacTable,
    fields: Readonly<Record<string, unknown>>,
  ): string {
    const foreignOrg = Object.hasOwn(fields, 'orgId') && fields.orgId !== orgId;
    if (Object.hasOwn(fields, 'table') || foreignOrg) throw new Error(MAC_FIELDS_INVALID);
    try {
      return canonicalJson({ table, ...fields });
    } catch {
      throw new Error(MAC_FIELDS_INVALID);
    }
  }

  private hmacHex(key: Buffer | null, message: string): string {
    if (key === null) throw new Error(INTEGRITY_KEY_UNAVAILABLE);
    try {
      return createHmac('sha256', key).update(message).digest('hex');
    } finally {
      key.fill(0);
    }
  }
}
