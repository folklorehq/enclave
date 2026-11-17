// UNWIRED: no composition root builds this yet.
import { sign } from 'node:crypto';
import type { HelpCenterReleaseSigner } from '@folklore/api';
import type { HelpCenterSigningKey } from '../sealing/keygen.js';
import { requireActivatedTenant } from './activated-tenant.js';
import type { HelpCenterAdapterDeps } from './ports.js';

const SIGNING_KEY_UNAVAILABLE = 'help_center_signing_key_unavailable';

export class EnclaveHelpCenterReleaseSigner implements HelpCenterReleaseSigner {
  constructor(private readonly deps: HelpCenterAdapterDeps) {}

  identity(orgId: string): { keyId: string; publicKey: string; epoch: number } {
    const key = this.signingKey(orgId);
    return { keyId: key.keyId, publicKey: key.publicKeyRaw.toString('base64'), epoch: key.epoch };
  }

  sign(orgId: string, payload: Buffer): { keyId: string; signature: string } {
    const key = this.signingKey(orgId);
    return { keyId: key.keyId, signature: sign(null, payload, key.privateKey).toString('base64') };
  }

  private signingKey(orgId: string): HelpCenterSigningKey {
    const { tenant, activation } = requireActivatedTenant(
      this.deps,
      orgId,
      SIGNING_KEY_UNAVAILABLE,
    );
    const key = tenant.helpCenterSigningKey(activation.signingKeyEpoch);
    if (key === null) throw new Error(SIGNING_KEY_UNAVAILABLE);
    return key;
  }
}
