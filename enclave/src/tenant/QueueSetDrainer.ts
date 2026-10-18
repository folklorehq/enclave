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
  PULL_FAILURE_PHASES,
  pullCompleteSignalSchema,
  pullFailedSignalSchema,
} from '@folklore/contracts/enclave';
import { PipelineProcessingError, type ProcessedFact } from '../pipeline/index.js';
import {
  buildPullFailedSignal,
  type PullCompleteSignal,
  type PullDueMessage,
  type PullFailedSignal,
} from '../pull/pull-runner.js';
import { pullFailureReason, type PullFailure } from '../pull/pull-failure-reason.js';
import { PullContinuations } from './continuation/PullContinuations.js';
import { HALT_POLL_INTERVAL_MS, type HaltGate } from '../control/HaltGate.js';
import { DurableAckBatch } from '../ingest/DurableAckBatch.js';
import { nextUpstreamMessage, upstreamCallScope } from '../inference/UpstreamCallScope.js';
import { PausableDeadline } from '../ingest/PausableDeadline.js';
import { IndexTurnQueue, withIndexTurn, type IndexTurn } from '../ingest/IndexTurnQueue.js';
import { ReceivedMessageLeases } from '../ingest/ReceivedMessageLeases.js';
import type { VisibilityHeartbeatTimers } from '../ingest/VisibilityHeartbeat.js';
import { errorType as classifyErrorType } from '../logging/error-fields.js';
import { jsonOutputPayload } from './output/json-output-payload.js';
import { EMIT_STEP_REASONS, type EmitStep } from './output/output-failure-reasons.js';
import {
  messageFailureCode,
  notProcessedFailureCode,
  type MessageFailurePhase,
} from './message-failure/message-failure-code.js';
import {
  parseRoutableMessage,
  TenantMessageRouteError,
  type RoutableMessage,
  type RoutedResult,
  type TenantMessageRouter,
} from './tenant-message-router.js';

// SQS long-poll budget shared across the assigned queues so a full sweep of N queues costs roughly
// one poll cycle (≈20s), preserving single-tenant timing at N=1.
const MAX_LONG_POLL_SECONDS = 20;
const RECEIVE_BATCH = 10;
const BATCH_TARGET = 50;
// Equals the tenant webhook queue's maxReceiveCount, pinned by a test against its definition.
export const PULL_FAILURE_RETRY_THRESHOLD = 3;
// An empty pool has no queue long-poll to pace the loop, so wait before re-checking for an assignment.
const EMPTY_POOL_POLL_INTERVAL_MS = 5_000;
// Equals the tenant webhook queue's VisibilityTimeout, pinned by a test against its definition.
export const MESSAGE_VISIBILITY_TIMEOUT_SECONDS = 120;
const MESSAGE_VISIBILITY_RENEWAL_MS = 40_000;
const INGEST_VISIBILITY_RENEWAL_FAILED = 'INGEST_VISIBILITY_RENEWAL_FAILED';
// Above one budgeted pull chunk with every embed slow; a route still running past it is wedged.
export const MESSAGE_PROCESSING_DEADLINE_MS = 30 * 60_000;
const MESSAGE_DEADLINE_EXCEEDED = 'message_deadline_exceeded';
type OutputPayload = ProcessedFact | PullCompleteSignal | PullFailedSignal;

export interface QueueAssignment {
  tenantId: string;
  queueUrl: string;
  assignmentGeneration?: number;
  rawPayloadsBucket?: string;
  processedBucket?: string;
}

// One message being worked: an SQS delivery under lease, or a pull chunk continued in-process.
interface HeldDelivery {
  body: string | undefined;
  archivable?: Message;
  release(): Promise<void>;
  ack(assignment: QueueAssignment): Promise<void>;
}

interface FailedOutcome {
  kind: 'failed';
  raw?: RoutableMessage;
  phase: MessageFailurePhase;
  error: unknown;
}

interface RoutedOutcome {
  kind: 'routed';
  raw: RoutableMessage;
  routed: RoutedResult;
}

type ParsedDelivery = { kind: 'parsed'; raw: RoutableMessage } | FailedOutcome;
type StageOutcome = RoutedOutcome | FailedOutcome | { kind: 'skipped' };

interface StagedDelivery {
  delivery: HeldDelivery;
  outcome: Promise<StageOutcome>;
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
  // Receives one closed-set code per failed message attempt, for visibility outside the enclave.
  onMessageFailure?: (code: string) => void;
  logger: Logger;
  visibilityTimers?: VisibilityHeartbeatTimers;
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
  private stopping = false;
  private readonly receiveAbort = new AbortController();
  private readonly drainIdleWaiters: Array<() => void> = [];
  private readonly evictingTenants = new Set<string>();
  private readonly leases: ReceivedMessageLeases;
  private readonly continuations = new PullContinuations();
  // Tracks the last value actually written, not merely the in-process idle transition: a freshly
  // booted process has no prior write, so its first non-idle sweep must write `false` unconditionally
  // — otherwise a stale `"1"` written before a prior self-stop survives the stop/start cycle and the
  // parent's systemd timer stops the host again before the enclave finishes booting.
  private lastWrittenIdle: boolean | undefined;

  constructor(private readonly deps: QueueSetDrainerDeps) {
    this.leases = new ReceivedMessageLeases(
      { sqs: deps.sqs, logger: deps.logger, timers: deps.visibilityTimers },
      {
        visibilityTimeoutSeconds: MESSAGE_VISIBILITY_TIMEOUT_SECONDS,
        renewalIntervalMs: MESSAGE_VISIBILITY_RENEWAL_MS,
        failureCode: INGEST_VISIBILITY_RENEWAL_FAILED,
      },
    );
  }

  async runForever(): Promise<void> {
    console.log('processing loop started', { queues: this.deps.assignments().length });
    while (!this.stopping) {
      // Pool-wide break-glass halt gates the whole sweep; a halted pool idles without touching any
      // queue. Per-tenant halts are applied per queue inside the sweep (§6.3).
      const halted = await this.deps.poolHalt.isHalted();
      if (this.stopping) break;
      if (halted) {
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
      const ackBatch = this.newAckBatch();
      const received = await this.drainAllQueues(assignments, ackBatch);
      await ackBatch.commit();
      const continued = await this.drainContinuations();
      await this.updateIdle(received || continued);
      await this.deps.onDrainComplete?.();
    } finally {
      await this.leases.releaseAll();
      this.activeDrains -= 1;
      if (this.activeDrains === 0) {
        for (const resolve of this.drainIdleWaiters.splice(0)) resolve();
      }
    }
  }

  // Aborts the long poll, lets the sweep in flight finish and starts no new one; false if it outlives the timeout.
  async stop(timeoutMs: number): Promise<boolean> {
    this.stopping = true;
    this.receiveAbort.abort();
    if (this.activeDrains === 0) return true;
    const drained = new Promise<boolean>((resolve) =>
      this.drainIdleWaiters.push(() => resolve(true)),
    );
    const timedOut = new Promise<boolean>((resolve) => {
      setTimeout(() => resolve(false), timeoutMs).unref();
    });
    return Promise.race([drained, timedOut]);
  }

  async evictTenant(tenantId: string): Promise<void> {
    this.evictingTenants.add(tenantId);
    if (this.activeDrains === 0) return;
    await new Promise<void>((resolve) => this.drainIdleWaiters.push(resolve));
  }

  finishTenantEviction(tenantId: string): void {
    this.evictingTenants.delete(tenantId);
  }

  private newAckBatch(): DurableAckBatch {
    return new DurableAckBatch(this.deps.logger, (step, error) =>
      this.reportMessageFailure(messageFailureCode(step, error)),
    );
  }

  // One chunk per source per sweep, after the queues: queued webhooks never wait behind a backfill.
  private async drainContinuations(): Promise<boolean> {
    if (this.stopping) return false;
    const pending = this.continuations.takeAll();
    if (pending.length === 0) return false;
    const ackBatch = this.newAckBatch();
    for (const { assignment, message } of pending) {
      if (!(await this.isStillDrainable(assignment))) continue;
      await this.handleDelivery(assignment, this.continuationDelivery(message), ackBatch);
    }
    await ackBatch.commit();
    return true;
  }

  // A dropped chunk is not lost: its cursor is persisted, so the next scheduled pull resumes there.
  private async isStillDrainable(assignment: QueueAssignment): Promise<boolean> {
    if (this.evictingTenants.has(assignment.tenantId)) return false;
    if (await this.deps.haltGateFor(assignment.tenantId).isHalted()) return false;
    return this.isCurrentAssignment(assignment);
  }

  private sqsDelivery(msg: Message): HeldDelivery {
    return {
      body: msg.Body,
      archivable: msg,
      release: async () => {
        await this.leases.release(msg);
      },
      ack: async (assignment) => {
        const receiptHandle = await this.leases.release(msg);
        await this.ackCurrentAssignment(assignment, receiptHandle!);
      },
    };
  }

  private continuationDelivery(message: RoutableMessage): HeldDelivery {
    return {
      body: JSON.stringify(message),
      release: async () => {},
      ack: async (assignment) => {
        if (!this.isCurrentAssignment(assignment)) throw new Error('assignment_changed_before_ack');
      },
    };
  }

  private async drainAllQueues(
    assignments: QueueAssignment[],
    ackBatch: DurableAckBatch,
  ): Promise<boolean> {
    let received = false;
    for (const assignment of assignments) {
      if (this.stopping) break;
      if (this.evictingTenants.has(assignment.tenantId)) continue;
      const halted = await this.deps.haltGateFor(assignment.tenantId).isHalted();
      if (halted || this.stopping) continue;
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
    while (total < BATCH_TARGET && !this.stopping) {
      const messages = await this.receive(assignment, isFirstPoll, queueCount);
      if (messages.length === 0) break;
      const fresh = await this.admitAll(assignment.queueUrl, messages);
      await this.handleBatch(
        assignment,
        fresh.map((msg) => this.sqsDelivery(msg)),
        ackBatch,
      );
      total += messages.length;
      isFirstPoll = false;
    }
    return total;
  }

  // A receive aborted by stop() reads as an empty queue.
  private async receive(
    assignment: QueueAssignment,
    isFirstPoll: boolean,
    queueCount: number,
  ): Promise<Message[]> {
    try {
      const resp = await this.deps.sqs.send(
        new ReceiveMessageCommand({
          QueueUrl: assignment.queueUrl,
          MaxNumberOfMessages: RECEIVE_BATCH,
          WaitTimeSeconds: isFirstPoll ? this.waitSeconds(queueCount) : 0,
        }),
        { abortSignal: this.receiveAbort.signal },
      );
      return resp.Messages ?? [];
    } catch (error) {
      if (this.stopping) return [];
      throw error;
    }
  }

  // Routing overlaps within one receive; emit and ack keep receive order, as a serial drain would.
  private async handleBatch(
    assignment: QueueAssignment,
    deliveries: HeldDelivery[],
    ackBatch: DurableAckBatch,
  ): Promise<void> {
    const staged = this.stageBatch(assignment, deliveries);
    const unfinished = [...staged];
    try {
      for (const { delivery, outcome } of staged) {
        await this.finishDelivery(assignment, delivery, await outcome, ackBatch);
        unfinished.shift();
      }
    } finally {
      await this.abandonUnfinished(unfinished.map((entry) => entry.outcome));
    }
  }

  // A pull is memory-heavy and advances source cursors, so it runs alone between webhook waves.
  private stageBatch(assignment: QueueAssignment, deliveries: HeldDelivery[]): StagedDelivery[] {
    const staged: StagedDelivery[] = [];
    const turns = new IndexTurnQueue();
    let lastPull: Promise<unknown> = Promise.resolve();
    for (const delivery of deliveries) {
      const parsed = this.parseDelivery(delivery);
      const isPull = parsed.kind === 'parsed' && this.isPullDue(parsed.raw);
      const turn = turns.next();
      const after = isPull ? Promise.all(staged.map((entry) => entry.outcome)) : lastPull;
      const outcome = after.then(() => this.stage(assignment, parsed, turn));
      if (isPull) lastPull = outcome;
      staged.push({ delivery, outcome });
    }
    return staged;
  }

  private async abandonUnfinished(unfinished: Promise<StageOutcome>[]): Promise<void> {
    for (const outcome of await Promise.all(unfinished)) {
      if (outcome.kind === 'routed') await this.releaseReplay(outcome.routed.releaseReplay);
    }
  }

  private parseDelivery(delivery: HeldDelivery): ParsedDelivery {
    try {
      const parsed: unknown = JSON.parse(delivery.body!);
      return { kind: 'parsed', raw: parseRoutableMessage(parsed) };
    } catch (error) {
      return { kind: 'failed', phase: 'parse', error };
    }
  }

  // Never rejects: a failure is an outcome, so one message cannot unwind its batch-mates.
  private async stage(
    assignment: QueueAssignment,
    parsed: ParsedDelivery,
    turn: IndexTurn = new IndexTurnQueue().next(),
  ): Promise<StageOutcome> {
    try {
      if (this.stopping || this.evictingTenants.has(assignment.tenantId))
        return { kind: 'skipped' };
      if (parsed.kind === 'failed') return parsed;
      return await this.route(assignment, parsed.raw, turn);
    } finally {
      turn.release();
    }
  }

  private async route(
    assignment: QueueAssignment,
    raw: RoutableMessage,
    turn: IndexTurn,
  ): Promise<StageOutcome> {
    try {
      const routed = await withIndexTurn(turn, () =>
        this.routeWithinDeadline(raw, assignment.tenantId, turn),
      );
      return { kind: 'routed', raw, routed };
    } catch (error) {
      return { kind: 'failed', raw, phase: 'route', error };
    }
  }

  private async handleDelivery(
    assignment: QueueAssignment,
    delivery: HeldDelivery,
    ackBatch: DurableAckBatch,
  ): Promise<void> {
    const outcome = await this.stage(assignment, this.parseDelivery(delivery));
    await this.finishDelivery(assignment, delivery, outcome, ackBatch);
  }

  private async finishDelivery(
    assignment: QueueAssignment,
    delivery: HeldDelivery,
    outcome: StageOutcome,
    ackBatch: DurableAckBatch,
  ): Promise<void> {
    if (outcome.kind === 'skipped') {
      await delivery.release();
      return;
    }
    if (outcome.kind === 'failed') {
      await this.failDelivery(assignment, delivery, outcome, undefined);
      return;
    }
    await this.completeRouted(assignment, delivery, outcome, ackBatch);
  }

  private async completeRouted(
    assignment: QueueAssignment,
    delivery: HeldDelivery,
    outcome: RoutedOutcome,
    ackBatch: DurableAckBatch,
  ): Promise<void> {
    const { raw, routed } = outcome;
    let releaseReplay = routed.releaseReplay;
    let phase: MessageFailurePhase = 'archive';
    try {
      const {
        context,
        facts,
        pullComplete,
        afterDurablePersistence,
        continuation,
        requiresDurablePersistence = true,
        shouldAcknowledge,
        commitReplay,
        droppedCode,
      } = routed;
      if (droppedCode) {
        this.deps.logger.warn('ingest_message_dropped', {
          tenant_id: context.tenantId,
          code: droppedCode,
        });
      } else if (delivery.archivable) {
        this.archive(
          context.tenantId,
          delivery.archivable,
          assignment.rawPayloadsBucket ?? this.deps.rawPayloadsBucket ?? '',
        );
      }
      phase = 'emit';
      await this.emitFacts(facts, assignment.assignmentGeneration);
      if (!shouldAcknowledge) {
        phase = 'release';
        this.reportMessageFailure(notProcessedFailureCode(routed.failureCode));
        await delivery.release();
        await this.releaseReplay(releaseReplay);
        releaseReplay = undefined;
        await this.recordPullFailure(raw, assignment, {
          phase: 'release',
          ...(routed.failureCode ? { code: routed.failureCode } : {}),
        });
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
        release: async () => {
          await delivery.release();
          await routed.releaseReplay?.();
        },
        ack: async () => {
          await delivery.ack(assignment);
          if (continuation) this.continuations.record(assignment, continuation);
        },
      });
      releaseReplay = undefined;
    } catch (error) {
      await this.failDelivery(
        assignment,
        delivery,
        { kind: 'failed', raw, phase, error },
        releaseReplay,
      );
    }
  }

  private async failDelivery(
    assignment: QueueAssignment,
    delivery: HeldDelivery,
    failure: FailedOutcome,
    releaseReplay: (() => Promise<void>) | undefined,
  ): Promise<void> {
    const { raw, error } = failure;
    let phase = failure.phase;
    let errorType = 'Error';
    await delivery.release();
    await this.releaseReplay(releaseReplay);
    // A pull runs its pipeline unwrapped, so its phase arrives on the pipeline error itself.
    if (error instanceof TenantMessageRouteError || error instanceof PipelineProcessingError) {
      phase = error.phase;
      errorType = error.errorType;
    } else {
      errorType = classifyErrorType(error);
    }
    // The fixed phase is content-free; an unassigned or cross-tenant message is never acked here,
    // so it stays in queue (then DLQ).
    // A tenant torn down mid-sweep (reassignment §4.3 zeroizes its context) lands here too — its
    // ingest key throws — so the message is left unacked and redelivered once reassigned; fail-closed.
    this.deps.logger.error('ingest_message_processing_failed', {
      phase,
      error_type: errorType,
    });
    // The release path already counted and reported this delivery before its signal failed to send.
    if (phase === 'release') return;
    this.reportMessageFailure(messageFailureCode(phase, error));
    if (raw?.tenant_id === assignment.tenantId) {
      await this.recordThrownPullFailure(raw, assignment, {
        phase: this.pullPhase(phase),
        error,
      });
    }
  }

  // Reporting is visibility only, so it can never be the thing that fails a message.
  private reportMessageFailure(code: string): void {
    try {
      this.deps.onMessageFailure?.(code);
    } catch {
      this.deps.logger.error('message_failure_report_failed');
    }
  }

  private async recordPullFailure(
    raw: RoutableMessage,
    assignment: QueueAssignment,
    failure: PullFailure,
  ): Promise<void> {
    const pending = this.pullFailureAfterRetry(raw, failure, assignment.assignmentGeneration);
    if (!pending) return;
    await this.emitPullFailed(pending.signal, assignment.assignmentGeneration);
    const state = this.pullFailures.get(pending.key);
    if (state) state.emitted = true;
  }

  // A thrown pull reaches the redrive limit too, so it must still produce its pull-failed signal.
  private async recordThrownPullFailure(
    raw: RoutableMessage,
    assignment: QueueAssignment,
    failure: PullFailure,
  ): Promise<void> {
    try {
      await this.recordPullFailure(raw, assignment, failure);
    } catch (error) {
      this.deps.logger.error('pull_failed_signal_emit_failed', {
        error_type: classifyErrorType(error),
      });
    }
  }

  private pullPhase(phase: string): PullFailure['phase'] {
    return (PULL_FAILURE_PHASES as readonly string[]).includes(phase)
      ? (phase as PullFailure['phase'])
      : 'route';
  }

  private async admitAll(queueUrl: string, messages: readonly Message[]): Promise<Message[]> {
    const fresh: Message[] = [];
    for (const msg of messages) {
      if (await this.leases.admit(queueUrl, msg)) fresh.push(msg);
    }
    return fresh;
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
    if (!this.isCurrentAssignment(assignment)) throw new Error('assignment_changed_before_ack');
    await this.ackMessage(assignment.queueUrl, receiptHandle);
  }

  private isCurrentAssignment(assignment: QueueAssignment): boolean {
    const current = this.deps
      .assignments()
      .find((candidate) => candidate.tenantId === assignment.tenantId);
    return (
      current !== undefined &&
      current.queueUrl === assignment.queueUrl &&
      (assignment.assignmentGeneration === undefined ||
        current.assignmentGeneration === assignment.assignmentGeneration)
    );
  }

  // Past the deadline the message is released and the route is told to stop; a late result is dropped.
  private async routeWithinDeadline(
    raw: RoutableMessage,
    tenantId: string,
    turn: IndexTurn,
  ): Promise<RoutedResult> {
    const controller = new AbortController();
    let expire: (reason: Error) => void = () => {};
    const expired = new Promise<never>((_, reject) => {
      expire = reject;
    });
    const deadline = new PausableDeadline(MESSAGE_PROCESSING_DEADLINE_MS, () => {
      const exceeded = new Error(MESSAGE_DEADLINE_EXCEEDED);
      controller.abort(exceeded);
      expire(exceeded);
    });
    turn.attachBudget(deadline);
    deadline.start();
    const routing = upstreamCallScope.run(
      {
        message: nextUpstreamMessage(),
        signal: controller.signal,
        background: true,
        waitBudget: deadline,
      },
      () => this.deps.router.route(raw, tenantId, { signal: controller.signal }),
    );
    try {
      return await Promise.race([routing, expired]);
    } catch (error) {
      if (controller.signal.aborted) this.discardLateRoute(routing);
      throw error;
    } finally {
      deadline.clear();
    }
  }

  private discardLateRoute(routing: Promise<RoutedResult>): void {
    routing.then(
      (late) => this.releaseReplay(late.releaseReplay),
      () => undefined,
    );
  }

  private async emitFacts(facts: ProcessedFact[], assignmentGeneration?: number): Promise<void> {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    for (const fact of facts) {
      await this.sendOutput({
        payload: fact,
        orgId: fact.orgId,
        deduplicationId: `processed-${fact.orgId}-${fact.factId}-${identity.assignmentGeneration}`,
        assignmentGeneration,
      });
    }
  }

  private async emitPullComplete(
    signal: PullCompleteSignal,
    assignmentGeneration?: number,
  ): Promise<void> {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    await this.sendOutput({
      payload: signal,
      orgId: signal.orgId,
      deduplicationId: `pull-complete-${signal.orgId}-${signal.sourceId}-${signal.completedAt}-${identity.assignmentGeneration}`,
      assignmentGeneration,
    });
  }

  private async emitPullFailed(
    signal: PullFailedSignal,
    assignmentGeneration?: number,
  ): Promise<void> {
    const identity = this.deps.outputIdentity(assignmentGeneration);
    await this.sendOutput({
      payload: signal,
      orgId: signal.orgId,
      deduplicationId: `pull-failed-${signal.orgId}-${signal.sourceId}-${signal.failedAt}-${identity.assignmentGeneration}`,
      nonce: this.pullFailureNonce(signal, assignmentGeneration),
      assignmentGeneration,
    });
  }

  private async sendOutput(output: {
    payload: OutputPayload;
    orgId: string;
    deduplicationId: string;
    nonce?: string;
    assignmentGeneration?: number;
  }): Promise<void> {
    const envelope = await this.authenticatedOutput(
      output.payload,
      output.nonce,
      output.assignmentGeneration,
    );
    const body = await this.emitStep('serialize', () => JSON.stringify(envelope));
    await this.emitStep('send', () =>
      this.deps.sqs.send(
        new SendMessageCommand({
          QueueUrl: this.deps.processedQueueUrl,
          MessageBody: body,
          MessageGroupId: `processed-${output.orgId}`,
          MessageDeduplicationId: output.deduplicationId,
        }),
      ),
    );
  }

  // Names the emit sub-step that threw; a cause the failure code already recognises still wins.
  private async emitStep<T>(step: EmitStep, run: () => T | Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error: unknown) {
      throw new Error(EMIT_STEP_REASONS[step], { cause: error });
    }
  }

  private pullFailureAfterRetry(
    raw: RoutableMessage,
    failure: PullFailure,
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
    return {
      key,
      signal: buildPullFailedSignal(
        raw,
        state.firstFailedAt,
        pullFailureReason(failure, state.attempts),
      ),
    };
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

  private async authenticatedOutput(
    payload: OutputPayload,
    nonce = randomBytes(32).toString('hex'),
    assignmentGeneration?: number,
  ): Promise<unknown> {
    const validated = await this.emitStep('validate', () => this.validatedOutput(payload));
    const binding = await this.emitStep('bind', () =>
      enclaveOutputBindingForPayload(validated, {
        ...this.deps.outputIdentity(assignmentGeneration),
        nonce,
      }),
    );
    return this.emitStep('sign', () => this.deps.outputAuthenticator.sign(binding));
  }

  // JSON reads an undefined member as absent, so dropping one first widens nothing the signer covers.
  private validatedOutput(payload: OutputPayload): OutputPayload {
    const json = jsonOutputPayload(payload);
    if ('type' in payload && payload.type === 'pull-complete') {
      return pullCompleteSignalSchema.parse(json);
    }
    if ('type' in payload && payload.type === 'pull-failed') {
      return pullFailedSignalSchema.parse(json);
    }
    return processedFactSchema.parse(json);
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
