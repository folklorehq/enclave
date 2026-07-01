import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';

const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

const FACT_BODY_PURPOSE = 'fact-body';

export interface FactBodyRef {
  factId: string;
  orgId: string;
}

// The enclave's single ESDK surface. Every fact-body ciphertext binds its row
// identity into the encryption context (AAD); every decrypt verifies it, so a
// ciphertext copied to a different fact's S3 key is rejected rather than served
// into the wrong row (ADL #12/#34). One place to audit crypto for the public mirror.
export class EnclaveCrypto {
  constructor(private readonly keyring: KmsKeyringNode) {}

  async encryptFactBody(plaintext: Buffer, ref: FactBodyRef & { sha256: string }): Promise<Buffer> {
    const { result } = await encrypt(this.keyring, plaintext, {
      encryptionContext: {
        factId: ref.factId,
        orgId: ref.orgId,
        purpose: FACT_BODY_PURPOSE,
        sha256: ref.sha256,
      },
    });
    return result;
  }

  async decryptFactBody(ciphertext: Buffer, expected: FactBodyRef): Promise<Buffer> {
    const { plaintext, messageHeader } = await decrypt(this.keyring, ciphertext);
    const ctx = messageHeader.encryptionContext;
    if (
      ctx['purpose'] !== FACT_BODY_PURPOSE ||
      ctx['factId'] !== expected.factId ||
      ctx['orgId'] !== expected.orgId
    ) {
      throw new Error('fact-body encryption context mismatch');
    }
    return Buffer.from(plaintext);
  }
}
