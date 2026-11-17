// UNWIRED: no composition root builds this yet.
import type { HelpCenterSealer, HelpCenterSealRef } from '@folklore/api';
import type { Logger } from '@folklore/core';
import { canonicalJsonHash, sha256Hex } from '@folklore/utils';
import { EncryptionContextMismatchError, type EnclaveCrypto } from '../crypto/esdk.js';
import { classifyEsdkFailure } from '../crypto/esdk-fault.js';
import type { TenantContext } from '../tenant/tenant-context.js';
import { requireActivatedTenant, resolveActivatedTenant } from './activated-tenant.js';
import type { HelpCenterAdapterDeps } from './ports.js';

const SEAL_KEY_UNAVAILABLE = 'help_center_seal_key_unavailable';
const SEAL_CONTENT_MISMATCH = 'help_center_seal_content_mismatch';
const UNSEAL_REFUSED_EVENT = 'help_center_unseal_refused';

type UnsealRefusal = 'context_mismatch' | 'content_hash_mismatch' | 'decrypt_failed';

export class EnclaveHelpCenterSealer implements HelpCenterSealer {
  constructor(private readonly deps: HelpCenterAdapterDeps & { readonly logger: Logger }) {}

  async seal(ref: HelpCenterSealRef, plaintext: Buffer): Promise<Buffer> {
    const { tenant } = requireActivatedTenant(this.deps, ref.orgId, SEAL_KEY_UNAVAILABLE);
    const crypto = this.cryptoOf(tenant);
    if (!this.matchesContentHash(ref, plaintext)) throw new Error(SEAL_CONTENT_MISMATCH);
    const sealing = crypto.encryptHelpCenterDocument(plaintext, ref);
    return sealing.catch((error: unknown) => {
      throw classifyEsdkFailure(error) === 'operational' ? new Error(SEAL_KEY_UNAVAILABLE) : error;
    });
  }

  async unseal(ref: HelpCenterSealRef, ciphertext: Buffer): Promise<Buffer | null> {
    const resolved = resolveActivatedTenant(this.deps, ref.orgId, SEAL_KEY_UNAVAILABLE);
    if (resolved === null) return null;
    // Starts before the try: an invalid ref throws its closed code instead of reading as tampering.
    const opening = this.cryptoOf(resolved.tenant).decryptHelpCenterDocument(ciphertext, ref);
    let plaintext: Buffer;
    try {
      plaintext = await opening;
    } catch (error) {
      return this.refuseOpen(ref.orgId, resolved.tenant, error);
    }
    if (this.matchesContentHash(ref, plaintext)) return plaintext;
    plaintext.fill(0);
    return this.refuse(ref.orgId, 'content_hash_mismatch');
  }

  // A teardown or service fault is operational and must not read as tampering.
  private refuseOpen(orgId: string, tenant: TenantContext, error: unknown): null {
    this.assertLive(tenant);
    if (classifyEsdkFailure(error) === 'operational') throw new Error(SEAL_KEY_UNAVAILABLE);
    const mismatch = error instanceof EncryptionContextMismatchError;
    return this.refuse(orgId, mismatch ? 'context_mismatch' : 'decrypt_failed');
  }

  private assertLive(tenant: TenantContext): void {
    this.cryptoOf(tenant);
  }

  private cryptoOf(tenant: TenantContext): EnclaveCrypto {
    try {
      return tenant.crypto;
    } catch {
      throw new Error(SEAL_KEY_UNAVAILABLE);
    }
  }

  private refuse(orgId: string, reason: UnsealRefusal): null {
    this.deps.logger.warn(UNSEAL_REFUSED_EVENT, { orgId, reason });
    return null;
  }

  private matchesContentHash(ref: HelpCenterSealRef, plaintext: Buffer): boolean {
    switch (ref.purpose) {
      case 'help-center-approval':
        return true;
      case 'help-center-revision':
        return this.revisionDigest(plaintext) === ref.contentHash;
      default:
        return sha256Hex(plaintext) === ref.contentHash;
    }
  }

  // The digest is recomputed from the parsed body, never read from a field the plaintext carries.
  private revisionDigest(plaintext: Buffer): string | null {
    try {
      const parsed: unknown = JSON.parse(plaintext.toString('utf8'));
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
      const { themeId, blocks } = parsed as Record<string, unknown>;
      return canonicalJsonHash({ themeId, blocks });
    } catch {
      return null;
    }
  }
}
