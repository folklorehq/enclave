import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';
import type { WikiCommentField } from '@folklore/contracts';
import type { SensitivityLevel } from '@folklore/wiki';

const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

const FACT_BODY_PURPOSE = 'fact-body';
const WIKI_ARTICLE_PURPOSE = 'wiki-article';
const WIKI_BLOCK_PURPOSE = 'wiki-block';
const TEAM_ONBOARDING_ARTICLE_PURPOSE = 'team-onboarding-article';
const TEAM_ONBOARDING_BLOCK_PURPOSE = 'team-onboarding-block';
const COLLAB_SNAPSHOT_PURPOSE = 'collab-snapshot';
const WIKI_COMMENT_PURPOSE = 'wiki-comment';
const WIKI_FEEDBACK_PURPOSE = 'wiki-feedback';
const LLM_CACHE_PURPOSE = 'llm-cache';
const OAUTH_CREDENTIAL_PURPOSE = 'oauth-credential';
const PULL_CURSOR_PURPOSE = 'pull-cursor';

export const WIKI_PUBLICATION_ENVELOPE_FORMAT = 'esdk-wiki-publication-v1';

export interface FactBodyRef {
  factId: string;
  orgId: string;
}

// A live-editing Yjs snapshot is the full current wiki prose; sealed to the fact key, bound to
// (org, page) so a snapshot relocated to another page fails to decrypt. Not bound to
// theme: a page's theme can be rewritten, which must not orphan it.
export interface CollabSnapshotRef {
  orgId: string;
  pageId: string;
}

// Wiki comment prose is customer content, sealed bound to (org, page, field) so a body relocated
// to another page — or an anchor excerpt swapped for a reply body — fails to decrypt.
export interface WikiCommentRef {
  orgId: string;
  pageId: string;
  field: WikiCommentField;
}

// A human-written AI-feedback correction is raw wiki prose, sealed bound to (org, block) so a
// correction relocated to another block fails to decrypt.
export interface WikiFeedbackRef {
  orgId: string;
  blockId: string;
}

// Content-addressed LLM-output cache (determinism #1): outputs are decrypted-content-derived, so
// the blob is sealed to the fact key bound to (org, cacheKey) — the cacheKey is the content-hash S3
// suffix, so a blob relocated/overwritten onto another key fails to decrypt.
export interface LlmCacheRef {
  orgId: string;
  cacheKey: string;
}

// The `code` connector's per-repo pull cursor carries raw file paths (content-derived), so it is
// sealed like every other tenant blob — enclave-written, enclave-read, never worker-readable.
export interface PullCursorRef {
  orgId: string;
  sourceId: string;
}

export interface OAuthCredentialRef {
  orgId: string;
  sourceKind: string;
  connectionId: string;
  purpose: 'access' | 'refresh';
  generation: string;
}

// Derived-knowledge is encrypted to the same key as fact bodies, but
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

// A cross-theme team-onboarding page is derived knowledge with no owning theme, so it binds to
// (org, team, audience) — a distinct purpose from wiki-article so a body cannot be relocated
// between a theme page and a team page.
export interface TeamOnboardingArticleRef {
  orgId: string;
  teamId: string;
  audienceId: string | null;
}

export interface TeamOnboardingBlockRef extends TeamOnboardingArticleRef {
  blockType: string;
}

export interface WikiPublicationSnapshotRef {
  purpose: 'wiki-publication-yjs';
  orgId: string;
  pageId: string;
  publicationId: string;
  parentPublicationId: string | null;
  revision: number;
  titleHash: string;
  markdownHash: string;
  policyHash: string;
}

export interface WikiPublishedBlockRef {
  purpose: 'wiki-publication-block';
  orgId: string;
  pageId: string;
  publicationId: string;
  blockId: string;
  logicalId: string;
  type: string;
  position: number;
  sensitivityLevel: SensitivityLevel;
  provenanceHash: string;
  contentHash: string;
}

function audienceKey(audienceId: string | null): string {
  return audienceId ?? 'all';
}

// Decrypt succeeded but the bound row identity didn't match — a ciphertext relocated to another
// row. Distinct from an infra/KMS decrypt failure so callers can tell an integrity
// event from a transient hiccup.
export class EncryptionContextMismatchError extends Error {
  constructor(purpose: string) {
    super(`${purpose} encryption context mismatch`);
    this.name = 'EncryptionContextMismatchError';
  }
}

// The enclave's single ESDK surface. Every ciphertext binds its row identity into
// the encryption context (AAD); every decrypt verifies it, so a ciphertext copied
// to a different row is rejected rather than served into the wrong one.
// One place to audit crypto for the public mirror.
export class EnclaveCrypto {
  encryptStorageCanary(plaintext: Buffer, orgId: string, generation: number): Promise<Buffer> {
    return this.seal(plaintext, {
      purpose: 'storage-canary',
      orgId,
      generation: String(generation),
    });
  }

  decryptStorageCanary(ciphertext: Buffer, orgId: string, generation: number): Promise<Buffer> {
    return this.openContext(
      ciphertext,
      { purpose: 'storage-canary', orgId, generation: String(generation) },
      'storage-canary',
    );
  }

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

  encryptTeamOnboardingArticle(plaintext: Buffer, ref: TeamOnboardingArticleRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      teamId: ref.teamId,
      audienceId: audienceKey(ref.audienceId),
      purpose: TEAM_ONBOARDING_ARTICLE_PURPOSE,
    });
  }

  decryptTeamOnboardingArticle(
    ciphertext: Buffer,
    expected: TeamOnboardingArticleRef,
  ): Promise<Buffer> {
    return this.open(ciphertext, TEAM_ONBOARDING_ARTICLE_PURPOSE, {
      orgId: expected.orgId,
      teamId: expected.teamId,
      audienceId: audienceKey(expected.audienceId),
    });
  }

  encryptTeamOnboardingBlock(plaintext: Buffer, ref: TeamOnboardingBlockRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      teamId: ref.teamId,
      audienceId: audienceKey(ref.audienceId),
      blockType: ref.blockType,
      purpose: TEAM_ONBOARDING_BLOCK_PURPOSE,
    });
  }

  decryptTeamOnboardingBlock(
    ciphertext: Buffer,
    expected: TeamOnboardingBlockRef,
  ): Promise<Buffer> {
    return this.open(ciphertext, TEAM_ONBOARDING_BLOCK_PURPOSE, {
      orgId: expected.orgId,
      teamId: expected.teamId,
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

  encryptPullCursor(plaintext: Buffer, ref: PullCursorRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      sourceId: ref.sourceId,
      purpose: PULL_CURSOR_PURPOSE,
    });
  }

  decryptPullCursor(ciphertext: Buffer, expected: PullCursorRef): Promise<Buffer> {
    return this.open(ciphertext, PULL_CURSOR_PURPOSE, {
      orgId: expected.orgId,
      sourceId: expected.sourceId,
    });
  }

  encryptOAuthCredential(plaintext: Buffer, ref: OAuthCredentialRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      sourceKind: ref.sourceKind,
      connectionId: ref.connectionId,
      credentialPurpose: ref.purpose,
      generation: ref.generation,
      purpose: OAUTH_CREDENTIAL_PURPOSE,
    });
  }

  decryptOAuthCredential(ciphertext: Buffer, expected: OAuthCredentialRef): Promise<Buffer> {
    return this.open(ciphertext, OAUTH_CREDENTIAL_PURPOSE, {
      orgId: expected.orgId,
      sourceKind: expected.sourceKind,
      connectionId: expected.connectionId,
      credentialPurpose: expected.purpose,
      generation: expected.generation,
    });
  }

  encryptWikiPublicationSnapshot(
    plaintext: Buffer,
    ref: WikiPublicationSnapshotRef,
  ): Promise<Buffer> {
    return this.seal(plaintext, this.publicationSnapshotContext(ref));
  }

  decryptWikiPublicationSnapshot(
    ciphertext: Buffer,
    expected: WikiPublicationSnapshotRef,
  ): Promise<Buffer> {
    return this.openContext(
      ciphertext,
      this.publicationSnapshotContext(expected),
      expected.purpose,
    );
  }

  encryptWikiPublishedBlock(plaintext: Buffer, ref: WikiPublishedBlockRef): Promise<Buffer> {
    return this.seal(plaintext, this.publishedBlockContext(ref));
  }

  decryptWikiPublishedBlock(ciphertext: Buffer, expected: WikiPublishedBlockRef): Promise<Buffer> {
    return this.openContext(ciphertext, this.publishedBlockContext(expected), expected.purpose);
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
    return this.openContext(ciphertext, { purpose, ...identity }, purpose);
  }

  private async openContext(
    ciphertext: Buffer,
    expected: Record<string, string>,
    purpose: string,
  ): Promise<Buffer> {
    const { plaintext, messageHeader } = await decrypt(this.keyring, ciphertext);
    const ctx = messageHeader.encryptionContext;
    const mismatch = Object.entries(expected).some(([key, value]) => ctx[key] !== value);
    if (mismatch) throw new EncryptionContextMismatchError(purpose);
    return Buffer.from(plaintext);
  }

  private publicationSnapshotContext(ref: WikiPublicationSnapshotRef): Record<string, string> {
    return {
      format: WIKI_PUBLICATION_ENVELOPE_FORMAT,
      purpose: ref.purpose,
      orgId: ref.orgId,
      pageId: ref.pageId,
      publicationId: ref.publicationId,
      parentPublicationId: ref.parentPublicationId ?? '',
      revision: String(ref.revision),
      titleHash: ref.titleHash,
      markdownHash: ref.markdownHash,
      policyHash: ref.policyHash,
    };
  }

  private publishedBlockContext(ref: WikiPublishedBlockRef): Record<string, string> {
    return {
      format: WIKI_PUBLICATION_ENVELOPE_FORMAT,
      purpose: ref.purpose,
      orgId: ref.orgId,
      pageId: ref.pageId,
      publicationId: ref.publicationId,
      blockId: ref.blockId,
      logicalId: ref.logicalId,
      type: ref.type,
      position: String(ref.position),
      sensitivityLevel: ref.sensitivityLevel,
      provenanceHash: ref.provenanceHash,
      contentHash: ref.contentHash,
    };
  }
}
