import { GetObjectCommand } from '@aws-sdk/client-s3';
import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
} from '@aws-sdk/client-sqs';
import type { KmsKeyringNode } from '@aws-crypto/client-node';
import type { S3Client } from '@aws-sdk/client-s3';
import type { SQSClient } from '@aws-sdk/client-sqs';
import { EnclaveCrypto } from '../crypto/esdk.js';
import { generate } from '../inference/phala.js';
import {
  synthesizeThemes,
  type ThemeSynthesisRequest,
  type ThemeSynthesisResult,
} from './theme-synthesis.js';

export interface SynthesisRequest {
  requestId: string;
  themeId: string;
  orgId: string;
  themeName: string;
  factRefs: { factId: string; s3Key: string; occurredAt: string; kind: string; score: number }[];
  relatedThemes: { themeId: string; name: string; similarity: number }[];
  contributorCount: number;
  audiences: { id: string | null; name: string }[];
}

interface SynthesisResult {
  type: 'wiki_synthesis';
  requestId: string;
  themeId: string;
  orgId: string;
  articles: { audienceId: string | null; content: string; factCount: number }[];
}

const SYSTEM_PROMPT =
  'You are a staff engineer writing a durable internal wiki page a teammate reads to understand a ' +
  'topic — not a changelog. Synthesize the source activity into knowledge: what this is and why it ' +
  'matters, how it works or what changed, and its current state. Organize by theme, never by date. ' +
  'Ground every claim in the provided sources; do not speculate beyond them. Use GitHub-flavored Markdown.';

const MAX_FACT_REFS = 30;

export interface SynthesisConsumerDeps {
  sqs: SQSClient;
  s3: S3Client;
  keyring: KmsKeyringNode;
  processedBucket: string;
  synthesisQueueUrl: string;
  processedQueueUrl: string;
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
            const raw = JSON.parse(msg.Body) as { type?: string };
            const result: SynthesisResult | ThemeSynthesisResult =
              raw.type === 'theme_synthesis'
                ? await synthesizeThemes(raw as ThemeSynthesisRequest, (s3Key, ref) =>
                    this.decryptBody(s3Key, ref),
                  )
                : await this.synthesize(raw as unknown as SynthesisRequest);
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
    const bodies = await Promise.all(
      req.factRefs
        .slice(0, MAX_FACT_REFS)
        .map((ref) => this.decryptBody(ref.s3Key, { factId: ref.factId, orgId: req.orgId })),
    );

    const relatedStr = req.relatedThemes
      .slice(0, 5)
      .map((r) => `- ${r.name} (similarity: ${r.similarity.toFixed(2)})`)
      .join('\n');

    const factLines = req.factRefs
      .slice(0, MAX_FACT_REFS)
      .map((ref, i) => {
        const body = bodies[i];
        if (!body) return null;
        const when = ref.occurredAt.slice(0, 10);
        return `- [${when}] (${ref.kind}) ${body.slice(0, 280)}`;
      })
      .filter((l): l is string => l !== null)
      .join('\n');

    const factCount = bodies.filter(Boolean).length;

    const articles = await Promise.all(
      req.audiences.map(async (audience) => {
        const audienceNote =
          audience.id === null
            ? 'General — for anyone in the org; explain plainly.'
            : `For the "${audience.name}" audience — outcomes and impact, concise, minimal code detail.`;

        const prompt = [
          `Topic: ${req.themeName}`,
          `Audience: ${audienceNote}`,
          '',
          'Write a wiki page with these sections:',
          '## Summary — 2-3 sentences: what this is and why it matters.',
          '## How it works — synthesized explanation (mechanisms, components, behavior), by theme, not a timeline.',
          '## Current state — where this stands now (done / in progress / known issues), if evident.',
          '## Sources — bullet each source below with its date, as a citation.',
          '',
          'Source activity to synthesize from (do NOT just replay it chronologically):',
          factLines || '(none)',
          relatedStr ? `\nRelated topics:\n${relatedStr}` : '',
          '',
          'Write the page now — synthesize into knowledge, organized by theme.',
        ].join('\n');

        const content = await generate(prompt, SYSTEM_PROMPT).catch(() => '');
        return { audienceId: audience.id, content: content.trim(), factCount };
      }),
    );

    return {
      type: 'wiki_synthesis',
      requestId: req.requestId,
      themeId: req.themeId,
      orgId: req.orgId,
      articles,
    };
  }

  private async decryptBody(
    s3Key: string,
    ref: { factId: string; orgId: string },
  ): Promise<string | null> {
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
      return (
        (content?.['body'] as string | undefined) ??
        (transition?.['transitionType'] as string | undefined) ??
        null
      );
    } catch {
      return null;
    }
  }
}
