import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  type Message,
  type SQSClient,
} from '@aws-sdk/client-sqs';
import type { Logger } from '@folklore/core';
import type { ProcessedFact } from '../pipeline/index.js';
import type { PullCompleteSignal } from '../pull/pull-runner.js';
import { HALT_POLL_INTERVAL_MS, type HaltGate } from '../control/halt-gate.js';
import { DurableAckBatch } from '../ingest/durable-ack-batch.js';
import type { RoutableMessage, TenantMessageRouter } from './tenant-message-router.js';

// SQS long-poll budget shared across the assigned queues so a full sweep of N queues costs roughly
// one poll cycle (≈20s), preserving single-tenant timing at N=1.
const MAX_LONG_POLL_SECONDS = 20;
const RECEIVE_BATCH = 10;
const BATCH_TARGET = 50;
// An empty pool has no queue long-poll to pace the loop, so wait before re-checking for an assignment.
const EMPTY_POOL_POLL_INTERVAL_MS = 5_000;

export interface QueueAssignment {
  tenantId: string;
  queueUrl: string;
}

export interface QueueSetDrainerDeps {
  sqs: SQSClient;
  s3: S3Client;
  router: TenantMessageRouter;
  // A supplier, not a fixed array: the assigned set changes live as the applier rebuilds the
  // registry on (re)assignment (§4.3), so each sweep drains the currently-assigned queues.
  assignments: () => QueueAssignment[];
  processedQueueUrl: string;
  processedOutputsBucket: string;
  rawPayloadsBucket: string;
  poolHalt: HaltGate;
  haltGateFor: (tenantId: string) => HaltGate;
  writeIdle: (idle: boolean) => Promise<void>;
  idlePollThreshold: number;
  onDrainComplete?: () => Promise<void>;
  logger: Logger;
}

// Drains the set of per-tenant webhook queues (design §5). Every message is routed to its own
// tenant's context (§2.2); a pool-wide halt skips the whole sweep, a per-tenant halt skips only
// that tenant's queue (§6.3); idle fires only when every assigned queue is empty. Acks flow through
// a per-sweep DurableAckBatch so a tenant's messages are deleted only after its HNSW index is
// persisted (#196) — a crash before that save redelivers (idempotent via deterministic factId),
// and one tenant's persist/ack failure never acks or blocks another's (batch groups by tenant).
export class QueueSetDrainer {
  private idlePolls = 0;
  private isIdle = false;

  constructor(private readonly deps: QueueSetDrainerDeps) {}

  async runForever(): Promise<void> {
    console.log('processing loop started', { queues: this.deps.assignments().length });
    for (;;) {
      // Pool-wide break-glass halt gates the whole sweep; a halted pool idles without touching any
      // queue (ADL #13). Per-tenant halts are applied per queue inside the sweep (§6.3).
      if (await this.deps.poolHalt.isHalted()) {
        await this.sleep(HALT_POLL_INTERVAL_MS);
        continue;
      }
      await this.drainOnce();
    }
  }

  async drainOnce(): Promise<void> {
    const assignments = this.deps.assignments();
    if (assignments.length === 0) {
      // An empty pool (assigned nothing yet, or drained to zero) waits for a manifest rather than
      // busy-spinning, and reports idle so the parent host can self-stop.
      await this.sleep(EMPTY_POOL_POLL_INTERVAL_MS);
      await this.updateIdle(false);
      return;
    }
    const ackBatch = new DurableAckBatch(this.deps.logger);
    const received = await this.drainAllQueues(assignments, ackBatch);
    await ackBatch.commit();
    await this.updateIdle(received);
    await this.deps.onDrainComplete?.();
  }

  private async drainAllQueues(
    assignments: QueueAssignment[],
    ackBatch: DurableAckBatch,
  ): Promise<boolean> {
    let received = false;
    for (const assignment of assignments) {
      if (await this.deps.haltGateFor(assignment.tenantId).isHalted()) continue;
      const count = await this.drainQueue(assignment, assignments.length, ackBatch);
      if (count > 0) received = true;
    }
    return received;
  }

  private async drainQueue(
    assignment: QueueAssignment,
    queueCount: number,
    ackBatch: DurableAckBatch,
  ): Promise<number> {
    let total = 0;
    let isFirstPoll = true;
    while (total < BATCH_TARGET) {
      const resp = await this.deps.sqs.send(
        new ReceiveMessageCommand({
          QueueUrl: assignment.queueUrl,
          MaxNumberOfMessages: RECEIVE_BATCH,
          WaitTimeSeconds: isFirstPoll ? this.waitSeconds(queueCount) : 0,
        }),
      );
      const messages = resp.Messages ?? [];
      if (messages.length === 0) break;
      for (const msg of messages) await this.handleMessage(assignment, msg, ackBatch);
      total += messages.length;
      isFirstPoll = false;
    }
    return total;
  }

  private async handleMessage(
    assignment: QueueAssignment,
    msg: Message,
    ackBatch: DurableAckBatch,
  ): Promise<void> {
    this.archive(assignment.tenantId, msg);
    try {
      const raw = JSON.parse(msg.Body!) as RoutableMessage;
      const { context, facts, pullComplete } = await this.deps.router.route(
        raw,
        assignment.tenantId,
      );
      await this.emitFacts(facts);
      if (pullComplete) await this.emitPullComplete(pullComplete);
      // #196: defer the delete — the message is acked only after this tenant's index is durably
      // persisted (batch commit), never before, so a crash redelivers instead of dropping an insert.
      ackBatch.add({
        tenantId: context.tenantId,
        hasUnsavedInserts: () => context.hnsw.hasUnsavedInserts(),
        persist: () =>
          context.hnsw.save(
            this.deps.s3,
            context.keyring,
            this.deps.processedOutputsBucket,
            context.tenantId,
          ),
        ack: () => this.ackMessage(assignment.queueUrl, msg.ReceiptHandle!),
      });
    } catch {
      // Content-free SQS id only — err could carry a decrypted-content snippet (ADL #18). An
      // unassigned or cross-tenant message is never acked here, so it stays in queue (then DLQ).
      // A tenant torn down mid-sweep (reassignment §4.3 zeroizes its context) lands here too — its
      // ingest key throws — so the message is left unacked and redelivered once reassigned; fail-closed.
      this.deps.logger.error('failed to process message', { id: msg.MessageId });
    }
  }

  private async ackMessage(queueUrl: string, receiptHandle: string): Promise<void> {
    await this.deps.sqs.send(
      new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: receiptHandle }),
    );
  }

  private async emitFacts(facts: ProcessedFact[]): Promise<void> {
    for (const fact of facts) {
      await this.deps.sqs.send(
        new SendMessageCommand({
          QueueUrl: this.deps.processedQueueUrl,
          MessageBody: JSON.stringify(fact),
          MessageGroupId: fact.orgId,
          MessageDeduplicationId: fact.factId,
        }),
      );
    }
  }

  private async emitPullComplete(signal: PullCompleteSignal): Promise<void> {
    await this.deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: this.deps.processedQueueUrl,
        MessageBody: JSON.stringify(signal),
        MessageGroupId: signal.orgId,
        MessageDeduplicationId: `pull-complete-${signal.sourceId}-${signal.completedAt}`,
      }),
    );
  }

  private archive(tenantId: string, msg: Message): void {
    if (!this.deps.rawPayloadsBucket || !msg.MessageId || !msg.Body) return;
    void this.deps.s3
      .send(
        new PutObjectCommand({
          Bucket: this.deps.rawPayloadsBucket,
          Key: this.archiveKey(tenantId, msg.MessageId),
          Body: msg.Body,
          ContentType: 'text/plain',
        }),
      )
      .catch(() => {});
  }

  private archiveKey(tenantId: string, messageId: string): string {
    const now = new Date();
    const month = String(now.getUTCMonth() + 1).padStart(2, '0');
    const day = String(now.getUTCDate()).padStart(2, '0');
    return `${tenantId}/${now.getUTCFullYear()}/${month}/${day}/${messageId}`;
  }

  private async updateIdle(received: boolean): Promise<void> {
    if (received) {
      this.idlePolls = 0;
      if (this.isIdle) {
        this.isIdle = false;
        await this.deps.writeIdle(false);
      }
      return;
    }
    this.idlePolls += 1;
    if (this.idlePolls >= this.deps.idlePollThreshold && !this.isIdle) {
      this.isIdle = true;
      await this.deps.writeIdle(true);
    }
  }

  private waitSeconds(queueCount: number): number {
    const share = Math.floor(MAX_LONG_POLL_SECONDS / queueCount);
    return Math.max(1, Math.min(MAX_LONG_POLL_SECONDS, share));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
