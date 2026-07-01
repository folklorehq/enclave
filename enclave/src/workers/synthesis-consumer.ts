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

export interface SynthesisRequest {
  requestId: string;
  conceptId: string;
  orgId: string;
  conceptName: string;
  factRefs: { factId: string; s3Key: string; occurredAt: string; kind: string; score: number }[];
  relatedConcepts: { conceptId: string; name: string; similarity: number }[];
  contributorCount: number;
  audiences: { id: string | null; name: string }[];
}

interface SynthesisResult {
  type: 'wiki_synthesis';
  requestId: string;
  conceptId: string;
  orgId: string;
  articles: { audienceId: string | null; content: string; factCount: number }[];
}

const SYSTEM_PROMPT =
  'You are a precise technical writer creating internal wiki articles for engineering teams. ' +
  'Write only from the provided source activity. Use GitHub-flavored Markdown. ' +
  'Structure: ## Overview, ## Key Activity, ## Contributors. ' +
  'Be factual and concise. Do not speculate beyond the provided evidence.';

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
            const req = JSON.parse(msg.Body) as SynthesisRequest;
            const result = await this.synthesize(req);
            await this.deps.sqs.send(
              new SendMessageCommand({
                QueueUrl: this.deps.processedQueueUrl,
                MessageBody: JSON.stringify(result),
                MessageGroupId: req.orgId,
                MessageDeduplicationId: req.requestId,
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

    const relatedStr = req.relatedConcepts
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
            ? 'General audience — accessible to everyone in the org.'
            : `Tailor depth and tone for the "${audience.name}" audience.`;

        const prompt = [
          `Concept: ${req.conceptName}`,
          `Audience: ${audienceNote}`,
          `Contributors: ${req.contributorCount}`,
          '',
          'Facts (chronological):',
          factLines || '(none)',
          '',
          'Related concepts:',
          relatedStr || '(none)',
          '',
          'Write the wiki article now.',
        ].join('\n');

        const content = await generate(prompt, SYSTEM_PROMPT).catch(() => '');
        return { audienceId: audience.id, content: content.trim(), factCount };
      }),
    );

    return {
      type: 'wiki_synthesis',
      requestId: req.requestId,
      conceptId: req.conceptId,
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
