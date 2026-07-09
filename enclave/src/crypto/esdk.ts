import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';

const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

const FACT_BODY_PURPOSE = 'fact-body';
const WIKI_ARTICLE_PURPOSE = 'wiki-article';
const WIKI_BLOCK_PURPOSE = 'wiki-block';

export interface FactBodyRef {
  factId: string;
  orgId: string;
}

// Derived-knowledge (ADL #12) is encrypted to the same key as fact bodies, but
// bound to its own row identity: the article to (org, theme, audience), each block
// to (org, theme, audience, blockType). `audienceKey` normalizes the all-members
// null so encrypt and read reconstruct the same context.
export interface WikiArticleRef {
  orgId: string;
  themeId: string;
  audienceId: string | null;
}

export interface WikiBlockRef extends WikiArticleRef {
  blockType: string;
}

function audienceKey(audienceId: string | null): string {
  return audienceId ?? 'all';
}

// The enclave's single ESDK surface. Every ciphertext binds its row identity into
// the encryption context (AAD); every decrypt verifies it, so a ciphertext copied
// to a different row is rejected rather than served into the wrong one (ADL #12/#34).
// One place to audit crypto for the public mirror.
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

  async encryptWikiArticle(plaintext: Buffer, ref: WikiArticleRef): Promise<Buffer> {
    const { result } = await encrypt(this.keyring, plaintext, {
      encryptionContext: {
        orgId: ref.orgId,
        themeId: ref.themeId,
        audienceId: audienceKey(ref.audienceId),
        purpose: WIKI_ARTICLE_PURPOSE,
      },
    });
    return result;
  }

  async decryptWikiArticle(ciphertext: Buffer, expected: WikiArticleRef): Promise<Buffer> {
    const { plaintext, messageHeader } = await decrypt(this.keyring, ciphertext);
    const ctx = messageHeader.encryptionContext;
    if (
      ctx['purpose'] !== WIKI_ARTICLE_PURPOSE ||
      ctx['orgId'] !== expected.orgId ||
      ctx['themeId'] !== expected.themeId ||
      ctx['audienceId'] !== audienceKey(expected.audienceId)
    ) {
      throw new Error('wiki-article encryption context mismatch');
    }
    return Buffer.from(plaintext);
  }

  async encryptWikiBlock(plaintext: Buffer, ref: WikiBlockRef): Promise<Buffer> {
    const { result } = await encrypt(this.keyring, plaintext, {
      encryptionContext: {
        orgId: ref.orgId,
        themeId: ref.themeId,
        audienceId: audienceKey(ref.audienceId),
        blockType: ref.blockType,
        purpose: WIKI_BLOCK_PURPOSE,
      },
    });
    return result;
  }

  async decryptWikiBlock(ciphertext: Buffer, expected: WikiBlockRef): Promise<Buffer> {
    const { plaintext, messageHeader } = await decrypt(this.keyring, ciphertext);
    const ctx = messageHeader.encryptionContext;
    if (
      ctx['purpose'] !== WIKI_BLOCK_PURPOSE ||
      ctx['orgId'] !== expected.orgId ||
      ctx['themeId'] !== expected.themeId ||
      ctx['audienceId'] !== audienceKey(expected.audienceId) ||
      ctx['blockType'] !== expected.blockType
    ) {
      throw new Error('wiki-block encryption context mismatch');
    }
    return Buffer.from(plaintext);
  }
}
