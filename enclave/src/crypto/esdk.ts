import { randomUUID } from 'node:crypto';
import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';
import type { WikiCommentField } from '@folklore/contracts';
import {
  sealedContentEnvelopeV1Schema,
  type SealedContentEnvelopeV1,
} from '@folklore/contracts/enclave';
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
const CODEBASE_SELECTION_PURPOSE = 'codebase-selection';
const JIRA_WEBHOOK_REPLAY_PURPOSE = 'jira-webhook-replay';

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

export interface CodebaseSelectionRef {
  orgId: string;
  deploymentId: string;
}

export interface JiraWebhookReplayRef {
  orgId: string;
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

type SealedBlockHeader = Omit<SealedContentEnvelopeV1, 'ciphertext' | 'purpose'> & {
  purpose: 'wiki-block' | 'team-onboarding-block';
};

export interface SealedContentKeyringConfig {
  activeVersion: number;
  keyrings: ReadonlyMap<number, KmsKeyringNode>;
}

export function singleVersionSealedContentKeyring(
  keyring: KmsKeyringNode,
): SealedContentKeyringConfig {
  return { activeVersion: 1, keyrings: new Map([[1, keyring]]) };
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

  private readonly sealedContentKeyrings: SealedContentKeyringConfig;

  constructor(
    private readonly keyring: KmsKeyringNode,
    sealedContentKeyrings: SealedContentKeyringConfig,
  ) {
    if (
      !Number.isSafeInteger(sealedContentKeyrings.activeVersion) ||
      sealedContentKeyrings.activeVersion < 1 ||
      !sealedContentKeyrings.keyrings.has(sealedContentKeyrings.activeVersion)
    ) {
      throw new Error('sealed content keyring configuration is invalid');
    }
    this.sealedContentKeyrings = sealedContentKeyrings;
  }

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

  async sealWikiBlockEnvelope(
    plaintext: Buffer,
    ref: WikiBlockRef,
  ): Promise<SealedContentEnvelopeV1> {
    return this.sealBlockEnvelope(
      plaintext,
      this.sealedBlockHeader(ref.orgId, WIKI_BLOCK_PURPOSE),
      {
        orgId: ref.orgId,
        themeId: ref.themeId,
        audienceId: audienceKey(ref.audienceId),
        blockType: ref.blockType,
      },
    );
  }

  async openWikiBlockEnvelope(envelope: unknown, expected: WikiBlockRef): Promise<Buffer> {
    const sealed = sealedContentEnvelopeV1Schema.parse(envelope);
    this.requireSealedBlockIdentity(sealed, expected.orgId, WIKI_BLOCK_PURPOSE);
    return this.openSealedBlockContext(
      Buffer.from(sealed.ciphertext, 'base64'),
      this.sealedBlockContext(sealed, {
        orgId: expected.orgId,
        themeId: expected.themeId,
        audienceId: audienceKey(expected.audienceId),
        blockType: expected.blockType,
      }),
      WIKI_BLOCK_PURPOSE,
    );
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

  async sealTeamOnboardingBlockEnvelope(
    plaintext: Buffer,
    ref: TeamOnboardingBlockRef,
  ): Promise<SealedContentEnvelopeV1> {
    return this.sealBlockEnvelope(
      plaintext,
      this.sealedBlockHeader(ref.orgId, TEAM_ONBOARDING_BLOCK_PURPOSE),
      {
        orgId: ref.orgId,
        teamId: ref.teamId,
        audienceId: audienceKey(ref.audienceId),
        blockType: ref.blockType,
      },
    );
  }

  async openTeamOnboardingBlockEnvelope(
    envelope: unknown,
    expected: TeamOnboardingBlockRef,
  ): Promise<Buffer> {
    const sealed = sealedContentEnvelopeV1Schema.parse(envelope);
    this.requireSealedBlockIdentity(sealed, expected.orgId, TEAM_ONBOARDING_BLOCK_PURPOSE);
    return this.openSealedBlockContext(
      Buffer.from(sealed.ciphertext, 'base64'),
      this.sealedBlockContext(sealed, {
        orgId: expected.orgId,
        teamId: expected.teamId,
        audienceId: audienceKey(expected.audienceId),
        blockType: expected.blockType,
      }),
      TEAM_ONBOARDING_BLOCK_PURPOSE,
    );
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

  encryptCodebaseSelection(plaintext: Buffer, ref: CodebaseSelectionRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      deploymentId: ref.deploymentId,
      purpose: CODEBASE_SELECTION_PURPOSE,
    });
  }

  decryptCodebaseSelection(ciphertext: Buffer, expected: CodebaseSelectionRef): Promise<Buffer> {
    return this.open(ciphertext, CODEBASE_SELECTION_PURPOSE, {
      orgId: expected.orgId,
      deploymentId: expected.deploymentId,
    });
  }

  encryptJiraWebhookReplay(plaintext: Buffer, ref: JiraWebhookReplayRef): Promise<Buffer> {
    return this.seal(plaintext, {
      orgId: ref.orgId,
      purpose: JIRA_WEBHOOK_REPLAY_PURPOSE,
    });
  }

  decryptJiraWebhookReplay(ciphertext: Buffer, expected: JiraWebhookReplayRef): Promise<Buffer> {
    return this.open(ciphertext, JIRA_WEBHOOK_REPLAY_PURPOSE, {
      orgId: expected.orgId,
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

  private async sealBlockEnvelope(
    plaintext: Buffer,
    header: SealedBlockHeader,
    identity: Record<string, string>,
  ): Promise<SealedContentEnvelopeV1> {
    const ciphertext = await this.sealWithKeyring(
      this.sealedContentKeyring(header.contentKeyVersion, header.purpose),
      plaintext,
      this.sealedBlockContext(header, identity),
    );
    return { ...header, ciphertext: ciphertext.toString('base64') };
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
    const mismatch =
      this.hasSealedEnvelopeMarker(ctx) ||
      Object.entries(expected).some(([key, value]) => ctx[key] !== value);
    if (mismatch) throw new EncryptionContextMismatchError(purpose);
    return Buffer.from(plaintext);
  }

  private async sealWithKeyring(
    keyring: KmsKeyringNode,
    plaintext: Buffer,
    encryptionContext: Record<string, string>,
  ): Promise<Buffer> {
    const { result } = await encrypt(keyring, plaintext, { encryptionContext });
    return result;
  }

  private async openSealedBlockContext(
    ciphertext: Buffer,
    expected: Record<string, string>,
    purpose: 'wiki-block' | 'team-onboarding-block',
  ): Promise<Buffer> {
    const { plaintext, messageHeader } = await decrypt(
      this.sealedContentKeyring(Number(expected.contentKeyVersion), purpose),
      ciphertext,
    );
    const mismatch = Object.entries(expected).some(
      ([key, value]) => messageHeader.encryptionContext[key] !== value,
    );
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

  private sealedBlockHeader(
    orgId: string,
    purpose: 'wiki-block' | 'team-onboarding-block',
  ): SealedBlockHeader {
    return {
      version: 1,
      algorithm: 'ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384',
      orgId,
      objectId: randomUUID(),
      purpose,
      formatVersion: 1,
      contentKeyVersion: this.sealedContentKeyrings.activeVersion,
    };
  }

  private sealedBlockContext(
    header: SealedBlockHeader,
    identity: Record<string, string>,
  ): Record<string, string> {
    return {
      version: String(header.version),
      algorithm: header.algorithm,
      orgId: header.orgId,
      objectId: header.objectId,
      purpose: header.purpose,
      formatVersion: String(header.formatVersion),
      contentKeyVersion: String(header.contentKeyVersion),
      ...identity,
    };
  }

  private requireSealedBlockIdentity(
    envelope: SealedContentEnvelopeV1,
    orgId: string,
    purpose: 'wiki-block' | 'team-onboarding-block',
  ): asserts envelope is SealedContentEnvelopeV1 & {
    purpose: 'wiki-block' | 'team-onboarding-block';
  } {
    if (envelope.orgId !== orgId || envelope.purpose !== purpose) {
      throw new EncryptionContextMismatchError(purpose);
    }
  }

  private sealedContentKeyring(
    version: number,
    purpose: 'wiki-block' | 'team-onboarding-block',
  ): KmsKeyringNode {
    const keyring = this.sealedContentKeyrings.keyrings.get(version);
    if (!keyring) throw new EncryptionContextMismatchError(purpose);
    return keyring;
  }

  private hasSealedEnvelopeMarker(encryptionContext: Record<string, string>): boolean {
    return ['version', 'algorithm', 'objectId', 'formatVersion', 'contentKeyVersion'].some(
      (key) => encryptionContext[key] !== undefined,
    );
  }
}
