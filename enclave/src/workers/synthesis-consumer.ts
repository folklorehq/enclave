import { GetObjectCommand } from '@aws-sdk/client-s3';
import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
} from '@aws-sdk/client-sqs';
import type { KmsKeyringNode } from '@aws-crypto/client-node';
import type { S3Client } from '@aws-sdk/client-s3';
import type { SQSClient } from '@aws-sdk/client-sqs';
import { buildArticlePrompt, redactForAudience } from '@folklore/wiki/synthesis';
import {
  articleToBlocks,
  enrichEmbedDrafts,
  type BlockDraft,
  type LinkPreviewFetcher,
} from '@folklore/wiki';
import type { LinkPreview } from '@folklore/contracts';
import { EnclaveCrypto } from '../crypto/esdk.js';
import { generate } from '../inference/phala.js';
import {
  synthesizeThemes,
  type ThemeSynthesisRequest,
  type ThemeSynthesisResult,
} from './theme-synthesis.js';

export interface SynthesisRequest {
  type: 'wiki_synthesis';
  requestId: string;
  themeId: string;
  orgId: string;
  themeName: string;
  themeType: string;
  parentThemeCount: number;
  factRefs: { factId: string; s3Key: string; occurredAt: string; kind: string; score: number }[];
  relatedThemes: { themeId: string; name: string; similarity: number }[];
  contributorCount: number;
  audiences: { id: string | null; name: string; publicEligible: boolean }[];
}

// ESDK ciphertext (base64) bound to the block's (org, theme, audience, type). The
// worker persists this verbatim into `wiki_blocks.body`; only the in-enclave API
// decrypts it (ADL #12). `sourceKinds` is filled in the worker from `factIds`, so
// the audience gate keeps running on cleartext metadata.
const WIKI_CONTENT_FORMAT = 'esdk-v1';

interface EncryptedBody {
  format: typeof WIKI_CONTENT_FORMAT;
  ciphertext: string;
}

interface EmittedBlock {
  type: string;
  sensitivityLevel: BlockDraft['sensitivityLevel'];
  audienceId: string | null;
  factIds: string[];
  body: EncryptedBody;
}

interface SynthesisResult {
  type: 'wiki_synthesis';
  requestId: string;
  themeId: string;
  orgId: string;
  articles: {
    audienceId: string | null;
    content: string;
    contentFormat: typeof WIKI_CONTENT_FORMAT | 'plaintext';
    factCount: number;
  }[];
  blocks: EmittedBlock[];
  citedFactIds: string[];
}

const MAX_FACT_REFS = 30;

export interface SynthesisConsumerDeps {
  sqs: SQSClient;
  s3: S3Client;
  keyring: KmsKeyringNode;
  processedBucket: string;
  synthesisQueueUrl: string;
  processedQueueUrl: string;
  // Egress-proxy link-preview fetch (ADL #54); absent in local/dev — embeds stay bare.
  previewFetcher?: LinkPreviewFetcher;
}

interface EmbedEnrichment {
  fetchPreview: LinkPreviewFetcher;
  redactNames: string[];
}

export class SynthesisConsumer {
  private readonly crypto: EnclaveCrypto;

  constructor(private readonly deps: SynthesisConsumerDeps) {
    this.crypto = new EnclaveCrypto(deps.keyring);
  }

  start(): void {
    void this.loop();
  }

  private async loop(): Promise<void> {
    for (;;) {
      try {
        const resp = await this.deps.sqs.send(
          new ReceiveMessageCommand({
            QueueUrl: this.deps.synthesisQueueUrl,
            MaxNumberOfMessages: 1,
            WaitTimeSeconds: 20,
          }),
        );
        for (const msg of resp.Messages ?? []) {
          if (!msg.Body || !msg.ReceiptHandle) continue;
          try {
            const raw = JSON.parse(msg.Body) as SynthesisRequest | ThemeSynthesisRequest;
            const result: SynthesisResult | ThemeSynthesisResult =
              raw.type === 'theme_synthesis'
                ? await synthesizeThemes(raw, (s3Key, ref) => this.decryptBody(s3Key, ref))
                : await this.synthesize(raw);
            await this.deps.sqs.send(
              new SendMessageCommand({
                QueueUrl: this.deps.processedQueueUrl,
                MessageBody: JSON.stringify(result),
                MessageGroupId: result.orgId,
                MessageDeduplicationId: result.requestId,
              }),
            );
            await this.deps.sqs.send(
              new DeleteMessageCommand({
                QueueUrl: this.deps.synthesisQueueUrl,
                ReceiptHandle: msg.ReceiptHandle,
              }),
            );
          } catch (err) {
            console.error('synthesis failed', { err });
            // Leave in queue — visibility timeout retries, DLQ after 3 attempts
          }
        }
      } catch (err) {
        console.error('synthesis poll failed', { err });
      }
    }
  }

  private async synthesize(req: SynthesisRequest): Promise<SynthesisResult> {
    const records = await Promise.all(
      req.factRefs
        .slice(0, MAX_FACT_REFS)
        .map((ref) => this.decryptFactRecord(ref.s3Key, { factId: ref.factId, orgId: req.orgId })),
    );
    const bodies = records.map((r) => r.body);
    // Contributor/system names decrypted here for synthesis double as the redaction
    // deny-list — a prompt cannot be trusted to keep them out of a public body (ADL #28).
    const internalNames = [...new Set(records.flatMap((r) => r.names))];

    const relatedLines = req.relatedThemes
      .slice(0, 5)
      .map((r) => `- ${r.name} (similarity: ${r.similarity.toFixed(2)})`)
      .join('\n');

    const cited: { factId: string; line: string }[] = [];
    req.factRefs.slice(0, MAX_FACT_REFS).forEach((ref, i) => {
      const body = bodies[i];
      if (!body) return;
      const when = ref.occurredAt.slice(0, 10);
      cited.push({
        factId: ref.factId,
        line: `- [${cited.length + 1}] [${when}] (${ref.kind}) ${body.slice(0, 280)}`,
      });
    });
    const factLines = cited.map((c) => c.line).join('\n');
    const citedFactIds = cited.map((c) => c.factId);
    const factCount = cited.length;

    // One body per audience off the SAME fact spine (ADL #51): the theme type picks the
    // section skeleton (ADR / postmortem / runbook / …), the audience projects it, and a
    // public body is hard-redacted before it leaves the enclave (ADL #28). Each drafted
    // body is then ESDK-encrypted (ADL #12) before it leaves the enclave.
    const drafted = await Promise.all(
      req.audiences.map(async (audience) => {
        const { system, prompt } = buildArticlePrompt({
          themeType: req.themeType,
          themeName: req.themeName,
          audience,
          factLines,
          relatedLines,
        });

        const generated = (await generate(prompt, system).catch(() => '')).trim();
        const content = redactForAudience(generated, audience.publicEligible, internalNames).text;
        return { audienceId: audience.id, content, publicEligible: audience.publicEligible };
      }),
    );

    const articles = await Promise.all(
      drafted.map((d) => this.encryptArticle(req, d.audienceId, d.content, factCount)),
    );

    const fetchPreview = this.memoizedPreviewFetcher();
    const blocks = (
      await Promise.all(
        drafted.map((d) =>
          this.encryptBlocks(req, d.audienceId, d.content, citedFactIds, {
            fetchPreview,
            redactNames: d.publicEligible ? internalNames : [],
          }),
        ),
      )
    ).flat();

    return {
      type: 'wiki_synthesis',
      requestId: req.requestId,
      themeId: req.themeId,
      orgId: req.orgId,
      articles,
      blocks,
      citedFactIds,
    };
  }

  private memoizedPreviewFetcher(): LinkPreviewFetcher {
    const cache = new Map<string, LinkPreview | null>();
    const fetcher = this.deps.previewFetcher;
    return async (url) => {
      if (cache.has(url)) return cache.get(url) ?? null;
      const result = fetcher ? await fetcher(url) : null;
      cache.set(url, result);
      return result;
    };
  }

  private async encryptArticle(
    req: SynthesisRequest,
    audienceId: string | null,
    content: string,
    factCount: number,
  ): Promise<SynthesisResult['articles'][number]> {
    if (!content) {
      return { audienceId, content: '', contentFormat: 'plaintext', factCount };
    }
    const ciphertext = await this.crypto.encryptWikiArticle(Buffer.from(content, 'utf8'), {
      orgId: req.orgId,
      themeId: req.themeId,
      audienceId,
    });
    return {
      audienceId,
      content: ciphertext.toString('base64'),
      contentFormat: WIKI_CONTENT_FORMAT,
      factCount,
    };
  }

  // The article is parsed into blocks in-enclave (the worker never sees prose);
  // each block body is encrypted, bound to its (org, theme, audience, type). Source
  // kinds are left to the worker to fill from `factIds` so the read gate stays on
  // cleartext metadata.
  private async encryptBlocks(
    req: SynthesisRequest,
    audienceId: string | null,
    content: string,
    citedFactIds: string[],
    enrichment: EmbedEnrichment,
  ): Promise<EmittedBlock[]> {
    if (!content) return [];
    const drafts = articleToBlocks(content, {
      citedFactIds,
      relatedThemes: req.relatedThemes.map((r) => ({ themeId: r.themeId, name: r.name })),
      factSources: new Map(),
    });
    const enriched = await enrichEmbedDrafts(drafts, enrichment.fetchPreview, {
      names: enrichment.redactNames,
    });
    return Promise.all(
      enriched.map(async (draft) => {
        const ciphertext = await this.crypto.encryptWikiBlock(
          Buffer.from(JSON.stringify(draft.body), 'utf8'),
          { orgId: req.orgId, themeId: req.themeId, audienceId, blockType: draft.type },
        );
        return {
          type: draft.type,
          sensitivityLevel: draft.sensitivityLevel,
          audienceId,
          factIds: draft.provenance.factIds ?? [],
          body: { format: WIKI_CONTENT_FORMAT, ciphertext: ciphertext.toString('base64') },
        };
      }),
    );
  }

  private async decryptBody(
    s3Key: string,
    ref: { factId: string; orgId: string },
  ): Promise<string | null> {
    return (await this.decryptFactRecord(s3Key, ref)).body;
  }

  private async decryptFactRecord(
    s3Key: string,
    ref: { factId: string; orgId: string },
  ): Promise<{ body: string | null; names: string[] }> {
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.processedBucket, Key: s3Key }),
      );
      const raw = await obj.Body!.transformToByteArray();
      const enc = Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
      // AAD verify: a ciphertext moved to another fact's S3 key is rejected here.
      const plaintext = await this.crypto.decryptFactBody(enc, ref);
      const fact = JSON.parse(plaintext.toString('utf8')) as Record<string, unknown>;
      const content = fact['content'] as Record<string, unknown> | undefined;
      const transition = fact['transition'] as Record<string, unknown> | undefined;
      const body =
        (content?.['body'] as string | undefined) ??
        (transition?.['transitionType'] as string | undefined) ??
        null;
      return { body, names: this.actorNames(fact['authors']) };
    } catch {
      return { body: null, names: [] };
    }
  }

  private actorNames(authors: unknown): string[] {
    if (!Array.isArray(authors)) return [];
    return authors
      .map((a) =>
        a && typeof a === 'object' ? (a as Record<string, unknown>)['displayName'] : undefined,
      )
      .filter((n): n is string => typeof n === 'string' && n.trim().length > 0);
  }
}
