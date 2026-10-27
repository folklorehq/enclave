import type { SsmParameterValuePort } from '../attestation/BootManifestSecretLoader.js';
import { SsmSecretLoader } from './SsmSecretLoader.js';

export const unsubscribeSecretLoadErrors = {
  read: 'unsubscribe_secret_read_failed',
  accessDenied: 'unsubscribe_secret_access_denied',
  missing: 'unsubscribe_secret_missing',
} as const;

/** The HMAC key behind one-click unsubscribe links; the caller decides what a failed read costs. */
export class UnsubscribeSecretLoader extends SsmSecretLoader {
  constructor(ssm: SsmParameterValuePort) {
    super(ssm, unsubscribeSecretLoadErrors);
  }
}
