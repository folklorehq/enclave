import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';
import type { WikiCommentField } from '@folklore/contracts';

const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

const FACT_BODY_PURPOSE = 'fact-body';
const WIKI_ARTICLE_PURPOSE = 'wiki-article';
const WIKI_BLOCK_PURPOSE = 'wiki-block';
const COLLAB_SNAPSHOT_PURPOSE = 'collab-snapshot';
const WIKI_COMMENT_PURPOSE = 'wiki-comment';
const WIKI_FEEDBACK_PURPOSE = 'wiki-feedback';
const LLM_CACHE_PURPOSE = 'llm-cache';

export interface FactBodyRef {
  factId: string;
  orgId: string;
}

// A live-editing Yjs snapshot is the full current wiki prose; sealed to the fact key, bound to
// (org, page) so a snapshot relocated to another page fails to decrypt (ADL #12). Not bound to
// theme: a page's theme can be rewritten (ADL #56 merge/aggregation), which must not orphan it.
export interface CollabSnapshotRef {
  orgId: string;
  pageId: string;
}

// Wiki comment prose is customer content, sealed bound to (org, page, field) so a body relocated
// to another page — or an anchor excerpt swapped for a reply body — fails to decrypt (ADL #12).
export interface WikiCommentRef {
  orgId: string;
  pageId: string;
  field: WikiCommentField;
}

// A human-written AI-feedback correction is raw wiki prose, sealed bound to (org, block) so a
// correction relocated to another block fails to decrypt (ADL #12/#45).
export interface WikiFeedbackRef {
  orgId: string;
  blockId: string;
}

// Content-addressed LLM-output cache (determinism #1): outputs are decrypted-content-derived, so
// the blob is sealed to the fact key bound to (org, cacheKey) — the cacheKey is the content-hash S3
// suffix, so a blob relocated/overwritten onto another key fails to decrypt (ADL #12).
export interface LlmCacheRef {
  orgId: string;
  cacheKey: string;
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

// Decrypt succeeded but the bound row identity didn't match — a ciphertext relocated to another
// row (ADL #12/#34). Distinct from an infra/KMS decrypt failure so callers can tell an integrity
// event from a transient hiccup.
export class EncryptionContextMismatchError extends Error {
  constructor(purpose: string) {
    super(`${purpose} encryption context mismatch`);
    this.name = 'EncryptionContextMismatchError';
  }
}

// The enclave's single ESDK surface. Every ciphertext binds its row identity into
// the encryption context (AAD); every decrypt verifies it, so a ciphertext copied
// to a different row is rejected rather than served into the wrong one (ADL #12/#34).
// One place to audit crypto for the public mirror.
export class EnclaveCrypto {
  constructor(private readonly keyring: KmsKeyringNode) {}

  encryptFactBody(plaintext: Buffer, ref: FactBodyRef & { sha256: string }): Promise<Buffer> {
    return this.seal(plaintext, {
      factId: ref.factId,
      orgId: ref.orgId,
      purpose: FACT_BODY_PURPOSE,
      sha256: ref.sha256,
    });
  }

  decryptFactBody(ciphertext: Buffer, expected: FactBodyRef): Promise<Buffer> {
    return this.open(ciphertext, FACT_BODY_PURPOSE, {
      factId: expected.factId,
      orgId: expected.orgId,
    });
  }

  encryptWikiArticle(plaintext: Buffer, ref: WikiArticleRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      themeId: ref.themeId,
      audienceId: audienceKey(ref.audienceId),
      purpose: WIKI_ARTICLE_PURPOSE,
    });
  }

  decryptWikiArticle(ciphertext: Buffer, expected: WikiArticleRef): Promise<Buffer> {
    return this.open(ciphertext, WIKI_ARTICLE_PURPOSE, {
      orgId: expected.orgId,
      themeId: expected.themeId,
      audienceId: audienceKey(expected.audienceId),
    });
  }

  encryptWikiBlock(plaintext: Buffer, ref: WikiBlockRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      themeId: ref.themeId,
      audienceId: audienceKey(ref.audienceId),
      blockType: ref.blockType,
      purpose: WIKI_BLOCK_PURPOSE,
    });
  }

  decryptWikiBlock(ciphertext: Buffer, expected: WikiBlockRef): Promise<Buffer> {
    return this.open(ciphertext, WIKI_BLOCK_PURPOSE, {
      orgId: expected.orgId,
      themeId: expected.themeId,
      audienceId: audienceKey(expected.audienceId),
      blockType: expected.blockType,
    });
  }

  encryptCollabSnapshot(plaintext: Buffer, ref: CollabSnapshotRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      pageId: ref.pageId,
      purpose: COLLAB_SNAPSHOT_PURPOSE,
    });
  }

  decryptCollabSnapshot(ciphertext: Buffer, expected: CollabSnapshotRef): Promise<Buffer> {
    return this.open(ciphertext, COLLAB_SNAPSHOT_PURPOSE, {
      orgId: expected.orgId,
      pageId: expected.pageId,
    });
  }

  encryptWikiComment(plaintext: Buffer, ref: WikiCommentRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      pageId: ref.pageId,
      field: ref.field,
      purpose: WIKI_COMMENT_PURPOSE,
    });
  }

  decryptWikiComment(ciphertext: Buffer, expected: WikiCommentRef): Promise<Buffer> {
    return this.open(ciphertext, WIKI_COMMENT_PURPOSE, {
      orgId: expected.orgId,
      pageId: expected.pageId,
      field: expected.field,
    });
  }

  encryptWikiFeedback(plaintext: Buffer, ref: WikiFeedbackRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      blockId: ref.blockId,
      purpose: WIKI_FEEDBACK_PURPOSE,
    });
  }

  decryptWikiFeedback(ciphertext: Buffer, expected: WikiFeedbackRef): Promise<Buffer> {
    return this.open(ciphertext, WIKI_FEEDBACK_PURPOSE, {
      orgId: expected.orgId,
      blockId: expected.blockId,
    });
  }

  encryptLlmCache(plaintext: Buffer, ref: LlmCacheRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      cacheKey: ref.cacheKey,
      purpose: LLM_CACHE_PURPOSE,
    });
  }

  decryptLlmCache(ciphertext: Buffer, expected: LlmCacheRef): Promise<Buffer> {
    return this.open(ciphertext, LLM_CACHE_PURPOSE, {
      orgId: expected.orgId,
      cacheKey: expected.cacheKey,
    });
  }

  private async seal(
    plaintext: Buffer,
    encryptionContext: Record<string, string>,
  ): Promise<Buffer> {
    const { result } = await encrypt(this.keyring, plaintext, { encryptionContext });
    return result;
  }

  // Decrypts and re-checks the bound `purpose` plus every identity field; any mismatch (a ciphertext
  // relocated to another row, or a legacy/plaintext blob that isn't a valid ESDK message) throws.
  private async open(
    ciphertext: Buffer,
    purpose: string,
    identity: Record<string, string>,
  ): Promise<Buffer> {
    const { plaintext, messageHeader } = await decrypt(this.keyring, ciphertext);
    const ctx = messageHeader.encryptionContext;
    const mismatch =
      ctx['purpose'] !== purpose ||
      Object.entries(identity).some(([key, value]) => ctx[key] !== value);
    if (mismatch) throw new EncryptionContextMismatchError(purpose);
    return Buffer.from(plaintext);
  }
}
