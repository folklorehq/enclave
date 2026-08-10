import type { EnclaveCrypto } from '../crypto/esdk.js';
import type { CredentialSealer } from './EnclaveOAuthAuthorizationService.js';

export class EnclaveOAuthCredentialSealer implements CredentialSealer {
  constructor(private readonly cryptoFor: (orgId: string) => EnclaveCrypto) {}

  async seal(input: Parameters<CredentialSealer['seal']>[0]): Promise<string> {
    try {
      const ciphertext = await this.cryptoFor(input.orgId).encryptOAuthCredential(input.plaintext, {
        orgId: input.orgId,
        sourceKind: input.sourceKind,
        connectionId: input.connectionId,
        purpose: input.purpose,
        generation: input.generation,
      });
      return ciphertext.toString('base64');
    } finally {
      input.plaintext.fill(0);
    }
  }
}
