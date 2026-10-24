import type { RecipientInfo } from '@aws-sdk/client-kms';
import type { KeyObject } from 'crypto';
import type { RecipientKeySource } from './RecipientKeyCache.js';

const KEY_ENCRYPTION_ALGORITHM = 'RSAES_OAEP_SHA_256';

export interface AttestedRecipient {
  recipient: RecipientInfo;
  privateKey: KeyObject;
}

export interface AttestedRecipientSource {
  withRecipient<T>(use: (recipient: AttestedRecipient) => Promise<T>): Promise<T>;
}

export type AttestationDocumentProvider = (publicKeyDer: Buffer) => Uint8Array;

// A document is attested per call, so no KMS request reuses one; only the key pair behind it is shared.
export class AttestedRecipients implements AttestedRecipientSource {
  constructor(
    private readonly keys: RecipientKeySource,
    private readonly attest: AttestationDocumentProvider,
  ) {}

  async withRecipient<T>(use: (recipient: AttestedRecipient) => Promise<T>): Promise<T> {
    const { publicKeyDer, privateKey } = await this.keys.acquire();
    return use({
      recipient: {
        KeyEncryptionAlgorithm: KEY_ENCRYPTION_ALGORITHM,
        AttestationDocument: this.attest(publicKeyDer),
      },
      privateKey,
    });
  }
}
