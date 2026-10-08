import { createHash, type KeyObject } from 'node:crypto';
import { eciesDecrypt } from '@folklore/crypto';
import {
  enclaveAuthorizationCodeGrantSchema,
  oauthCodeGrantAad,
  type EnclaveAuthorizationCodeGrant,
} from '@folklore/contracts/enclave';

export interface SealedCodeGrantEnvelope {
  encryptedCodeGrant: string;
  ciphertextSha256: string;
}

export class SealedCodeGrantOpenError extends Error {
  constructor() {
    super('sealed_code_grant_invalid');
    this.name = 'SealedCodeGrantOpenError';
  }
}

export class SealedCodeGrantOpener {
  constructor(private readonly privateKey: KeyObject) {}

  open(envelope: SealedCodeGrantEnvelope): EnclaveAuthorizationCodeGrant {
    try {
      if (this.hash(envelope.encryptedCodeGrant) !== envelope.ciphertextSha256) {
        throw new SealedCodeGrantOpenError();
      }
      const message = JSON.parse(envelope.encryptedCodeGrant) as Parameters<typeof eciesDecrypt>[0];
      const grant = this.decrypt(message);
      // The AAD is derived from the grant, so a second open under it proves the envelope bound it.
      const checked = this.decrypt(message, oauthCodeGrantAad(grant));
      if (JSON.stringify(checked) !== JSON.stringify(grant)) throw new SealedCodeGrantOpenError();
      return grant;
    } catch {
      throw new SealedCodeGrantOpenError();
    }
  }

  private decrypt(
    message: Parameters<typeof eciesDecrypt>[0],
    aad?: string,
  ): EnclaveAuthorizationCodeGrant {
    const plaintext = eciesDecrypt(message, this.privateKey, aad);
    try {
      return enclaveAuthorizationCodeGrantSchema.parse(JSON.parse(plaintext.toString('utf8')));
    } finally {
      plaintext.fill(0);
    }
  }

  private hash(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }
}
