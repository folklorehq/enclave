import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  type Message,
  type SQSClient,
} from '@aws-sdk/client-sqs';
import type { Logger } from '@folklore/core';
import { createHash, randomBytes } from 'node:crypto';
import {
  enclaveOutputBindingForPayload,
  type EnclaveOutputAuthenticator,
} from '@folklore/contracts/enclave-output';
import {
  processedFactSchema,
  pullCompleteSignalSchema,
  pullFailedSignalSchema,
} from '@folklore/contracts/enclave';
import type { ProcessedFact } from '../pipeline/index.js';
import {
  buildPullFailedSignal,
  type PullCompleteSignal,
  type PullDueMessage,
  type PullFailedSignal,
} from '../pull/pull-runner.js';
import { HALT_POLL_INTERVAL_MS, type HaltGate } from '../control/HaltGate.js';
import { DurableAckBatch } from '../ingest/DurableAckBatch.js';
import {
  parseRoutableMessage,
  type RoutableMessage,
  type TenantMessageRouter,
} from './tenant-message-router.js';

// SQS long-poll budget shared across the assigned queues so a full sweep of N queues costs roughly
// one poll cycle (≈20s), preserving single-tenant timing at N=1.
const MAX_LONG_POLL_SECONDS = 20;
const RECEIVE_BATCH = 10;
const BATCH_TARGET = 50;
const PULL_FAILURE_RETRY_THRESHOLD = 3;
// An empty pool has no queue long-poll to pace the loop, so wait before re-checking for an assignment.
const EMPTY_POOL_POLL_INTERVAL_MS = 5_000;

export interface QueueAssignment {
  tenantId: string;
  queueUrl: string;
  assignmentGeneration?: number;
  rawPayloadsBucket?: string;
  processedBucket?: string;
}

interface PullFailureState {
  attempts: number;
  firstFailedAt: Date;
  emitted: boolean;
}

export interface QueueSetDrainerDeps {
  sqs: SQSClient;
  s3: S3Client;
  router: TenantMessageRouter;
  // A supplier, not a fixed array: the assigned set changes live as the applier rebuilds the
  // registry on (re)assignment (§4.3), so each sweep drains the currently-assigned queues.
  assignments: () => QueueAssignment[];
  processedQueueUrl: string;
  processedOutputsBucket?: string;
  rawPayloadsBucket?: string;
  outputAuthenticator: EnclaveOutputAuthenticator;
  outputIdentity: (assignmentGeneration?: number) => {
    deploymentId: string;
    assignmentGeneration: number;
  };
  poolHalt: HaltGate;
  haltGateFor: (tenantId: string) => HaltGate;
  writeIdle: (idle: boolean) => Promise<void>;
  idlePollThreshold: number;
  // Activity the queues cannot see — a reader on the box API, a live editing session, an in-flight
  // synthesis — counts as a busy poll, so the host is never stopped out from under it.
  isBusy?: () => boolean;
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
  private readonly pullFailures = new Map<string, PullFailureState>();
  private activeDrains = 0;
  private readonly drainIdleWaiters: Array<() => void> = [];
  private readonly evictingTenants = new Set<string>();
  // Tracks the last value actually written, not merely the in-process idle transition: a freshly
  // booted process has no prior write, so its first non-idle sweep must write `false` unconditionally
  // — otherwise a stale `"1"` written before a prior self-stop survives the stop/start cycle and the
  // parent's systemd timer stops the host again before the enclave finishes booting.
  private lastWrittenIdle: boolean | undefined;

  constructor(private readonly deps: QueueSetDrainerDeps) {}

  async runForever(): Promise<void> {
    console.log('processing loop started', { queues: this.deps.assignments().length });
    for (;;) {
      // Pool-wide break-glass halt gates the whole sweep; a halted pool idles without touching any
      // queue. Per-tenant halts are applied per queue inside the sweep (§6.3).
      if (await this.deps.poolHalt.isHalted()) {
        await this.sleep(HALT_POLL_INTERVAL_MS);
        continue;
      }
      await this.drainOnce();
    }
  }

  async drainOnce(): Promise<void> {
    this.activeDrains += 1;
    try {
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
    } finally {
      this.activeDrains -= 1;
      if (this.activeDrains === 0) {
        for (const resolve of this.drainIdleWaiters.splice(0)) resolve();
      }
    }
  }

  async evictTenant(tenantId: string): Promise<void> {
    this.evictingTenants.add(tenantId);
    if (this.activeDrains === 0) return;
    await new Promise<void>((resolve) => this.drainIdleWaiters.push(resolve));
  }

  finishTenantEviction(tenantId: string): void {
    this.evictingTenants.delete(tenantId);
  }

  private async drainAllQueues(
    assignments: QueueAssignment[],
    ackBatch: DurableAckBatch,
  ): Promise<boolean> {
    let received = false;
    for (const assignment of assignments) {
      if (this.evictingTenants.has(assignment.tenantId)) continue;
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
      for (const msg of messages) {
        if (this.evictingTenants.has(assignment.tenantId)) break;
        await this.handleMessage(assignment, msg, ackBatch);
      }
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
    let releaseReplay: (() => Promise<void>) | undefined;
    try {
      const parsed: unknown = JSON.parse(msg.Body!);
      const raw = parseRoutableMessage(parsed);
      const routed = await this.deps.router.route(raw, assignment.tenantId);
      releaseReplay = routed.releaseReplay;
      const {
        context,
        facts,
        pullComplete,
        afterDurablePersistence,
        requiresDurablePersistence = true,
        shouldAcknowledge,
        commitReplay,
      } = routed;
      this.archive(
        context.tenantId,
        msg,
        assignment.rawPayloadsBucket ?? this.deps.rawPayloadsBucket ?? '',
      );
      await this.emitFacts(facts, assignment.assignmentGeneration);
      if (!shouldAcknowledge) {
        await this.releaseReplay(releaseReplay);
        releaseReplay = undefined;
        const failure = this.pullFailureAfterRetry(raw, assignment.assignmentGeneration);
        if (failure) {
          await this.emitPullFailed(failure.signal, assignment.assignmentGeneration);
          const state = this.pullFailures.get(failure.key);
          if (state) state.emitted = true;
        }
        return;
      }
      // #196: defer the delete — the message is acked only after this tenant's index is durably
      // persisted (batch commit), never before, so a crash redelivers instead of dropping an insert.
      ackBatch.add({
        tenantId: context.tenantId,
        hasUnsavedInserts: () => requiresDurablePersistence && context.hnsw.hasUnsavedInserts(),
        persist: async () => {
          if (!requiresDurablePersistence) return;
          await context.hnsw.save(
            this.deps.s3,
            context.keyring,
            assignment.processedBucket || this.deps.processedOutputsBucket || '',
            context.tenantId,
          );
        },
        afterDurablePersistence: async () => {
          await afterDurablePersistence?.();
          if (pullComplete) {
            await this.emitPullComplete(pullComplete, assignment.assignmentGeneration);
            this.pullFailures.delete(
              this.pullFailureKey(pullComplete, assignment.assignmentGeneration),
            );
          }
        },
        afterPersist: commitReplay,
        release: routed.releaseReplay,
        ack: () => this.ackCurrentAssignment(assignment, msg.ReceiptHandle!),
      });
      releaseReplay = undefined;
    } catch {
      await this.releaseReplay(releaseReplay);
      // Content-free SQS id only — err could carry a decrypted-content snippet. An
      // unassigned or cross-tenant message is never acked here, so it stays in queue (then DLQ).
      // A tenant torn down mid-sweep (reassignment §4.3 zeroizes its context) lands here too — its
      // ingest key throws — so the message is left unacked and redelivered once reassigned; fail-closed.
      this.deps.logger.error('failed to process message', { id: msg.MessageId });
    }
  }

  private async releaseReplay(release: (() => Promise<void>) | undefined): Promise<void> {
    if (!release) return;
    try {
      await release();
    } catch {
      this.deps.logger.error('replay release failed — message left in queue for retry');
    }
  }

  private async ackMessage(queueUrl: string, receiptHandle: string): Promise<void> {
    await this.deps.sqs.send(
      new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: receiptHandle }),
    );
  }

  private async ackCurrentAssignment(
    assignment: QueueAssignment,
    receiptHandle: string,
  ): Promise<void> {
    const current = this.deps
      .assignments()
      .find((candidate) => candidate.tenantId === assignment.tenantId);
    if (
      !current ||
      current.queueUrl !== assignment.queueUrl ||
      (assignment.assignmentGeneration !== undefined &&
        current.assignmentGeneration !== assignment.assignmentGeneration)
    ) {
      throw new Error('assignment_changed_before_ack');
    }
    await this.ackMessage(assignment.queueUrl, receiptHandle);
  }

  private async emitFacts(facts: ProcessedFact[], assignmentGeneration?: number): Promise<void> {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    for (const fact of facts) {
      const output = this.authenticatedOutput(fact, undefined, assignmentGeneration);
      await this.deps.sqs.send(
        new SendMessageCommand({
          QueueUrl: this.deps.processedQueueUrl,
          MessageBody: JSON.stringify(output),
          MessageGroupId: `processed-${fact.orgId}`,
          MessageDeduplicationId: `processed-${fact.orgId}-${fact.factId}-${identity.assignmentGeneration}`,
        }),
      );
    }
  }

  private async emitPullComplete(
    signal: PullCompleteSignal,
    assignmentGeneration?: number,
  ): Promise<void> {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    const output = this.authenticatedOutput(signal, undefined, assignmentGeneration);
    await this.deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: this.deps.processedQueueUrl,
        MessageBody: JSON.stringify(output),
        MessageGroupId: `processed-${signal.orgId}`,
        MessageDeduplicationId: `pull-complete-${signal.orgId}-${signal.sourceId}-${signal.completedAt}-${identity.assignmentGeneration}`,
      }),
    );
  }

  private async emitPullFailed(
    signal: PullFailedSignal,
    assignmentGeneration?: number,
  ): Promise<void> {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    const output = this.authenticatedOutput(
      signal,
      this.pullFailureNonce(signal, assignmentGeneration),
      assignmentGeneration,
    );
    await this.deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: this.deps.processedQueueUrl,
        MessageBody: JSON.stringify(output),
        MessageGroupId: `processed-${signal.orgId}`,
        MessageDeduplicationId: `pull-failed-${signal.orgId}-${signal.sourceId}-${signal.failedAt}-${identity.assignmentGeneration}`,
      }),
    );
  }

  private pullFailureAfterRetry(
    raw: RoutableMessage,
    assignmentGeneration?: number,
  ): { key: string; signal: PullFailedSignal } | undefined {
    if (!this.isPullDue(raw)) return undefined;
    const key = this.pullFailureKey(raw, assignmentGeneration);
    const state = this.pullFailures.get(key) ?? {
      attempts: 0,
      firstFailedAt: new Date(),
      emitted: false,
    };
    state.attempts += 1;
    this.pullFailures.set(key, state);
    if (state.emitted || state.attempts < PULL_FAILURE_RETRY_THRESHOLD) return undefined;
    return { key, signal: buildPullFailedSignal(raw, state.firstFailedAt) };
  }

  private pullFailureKey(
    input: PullDueMessage | PullCompleteSignal,
    assignmentGeneration?: number,
  ): string {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    return `${identity.deploymentId}:${identity.assignmentGeneration}:${'tenant_id' in input ? input.tenant_id : input.orgId}:${'kind' in input ? input.kind : input.sourceKind}:${input.sourceId}`;
  }

  private pullFailureNonce(signal: PullFailedSignal, assignmentGeneration?: number): string {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    return createHash('sha256')
      .update(
        `folklore.pull-failed.v1\0${identity.deploymentId}\0${identity.assignmentGeneration}\0${signal.orgId}\0${signal.sourceKind}\0${signal.sourceId}\0${signal.failedAt}`,
      )
      .digest('hex');
  }

  private isPullDue(raw: RoutableMessage): raw is PullDueMessage {
    return raw.type === 'pull-due';
  }

  private authenticatedOutput(
    payload: ProcessedFact | PullCompleteSignal | PullFailedSignal,
    nonce = randomBytes(32).toString('hex'),
    assignmentGeneration?: number,
  ): unknown {
    const validated =
      'type' in payload && payload.type === 'pull-complete'
        ? pullCompleteSignalSchema.parse(payload)
        : 'type' in payload && payload.type === 'pull-failed'
          ? pullFailedSignalSchema.parse(payload)
          : processedFactSchema.parse(payload);
    return this.deps.outputAuthenticator.sign(
      enclaveOutputBindingForPayload(validated, {
        ...this.deps.outputIdentity(assignmentGeneration),
        nonce,
      }),
    );
  }

  private archive(tenantId: string, msg: Message, bucket: string): void {
    const archiveBucket = bucket || this.deps.rawPayloadsBucket || '';
    if (!archiveBucket || !msg.MessageId || !msg.Body) return;
    void this.deps.s3
      .send(
        new PutObjectCommand({
          Bucket: archiveBucket,
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
    const active = received || (this.deps.isBusy?.() ?? false);
    if (active) {
      this.idlePolls = 0;
      await this.writeIdleIfChanged(false);
      return;
    }
    this.idlePolls += 1;
    if (this.idlePolls >= this.deps.idlePollThreshold) {
      await this.writeIdleIfChanged(true);
    }
  }

  private async writeIdleIfChanged(idle: boolean): Promise<void> {
    if (this.lastWrittenIdle === idle) return;
    this.lastWrittenIdle = idle;
    await this.deps.writeIdle(idle);
  }

  private waitSeconds(queueCount: number): number {
    const share = Math.floor(MAX_LONG_POLL_SECONDS / queueCount);
    return Math.max(1, Math.min(MAX_LONG_POLL_SECONDS, share));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
