import { ChangeMessageVisibilityCommand, type SQSClient } from '@aws-sdk/client-sqs';
import type { Logger } from '@folklore/core';
import { errorType } from '../logging/error-fields.js';

const RENEWAL_ATTEMPTS = 3;
const RENEWAL_RETRY_BASE_MS = 250;

export interface VisibilityHeartbeatTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const SYSTEM_VISIBILITY_TIMERS: VisibilityHeartbeatTimers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export interface VisibilityHeartbeatDeps {
  sqs: Pick<SQSClient, 'send'>;
  logger: Logger;
  timers?: VisibilityHeartbeatTimers;
}

export interface VisibilityLease {
  queueUrl: string;
  receiptHandle: string;
  visibilityTimeoutSeconds: number;
  renewalIntervalMs: number;
  // Fixed, content-free code carried by the failure log line and the assertHealthy error.
  failureCode: string;
  // When set, a failed renewal round is logged and the next interval tries again instead of ending.
  keepRenewingAfterFailure?: boolean;
}

/** Keeps one received SQS message invisible while it is worked on, until stopped. */
export class VisibilityHeartbeat {
  private isStopped = false;
  private wake: (() => void) | undefined;
  private loopPromise: Promise<void> | undefined;
  private failure: Error | undefined;
  private readonly timers: VisibilityHeartbeatTimers;

  constructor(
    private readonly deps: VisibilityHeartbeatDeps,
    private readonly lease: VisibilityLease,
  ) {
    this.timers = deps.timers ?? SYSTEM_VISIBILITY_TIMERS;
  }

  start(): void {
    this.loopPromise ??= this.loop();
  }

  async stop(): Promise<void> {
    this.isStopped = true;
    this.wake?.();
    await this.loopPromise;
  }

  assertHealthy(): void {
    if (this.failure) throw this.failure;
  }

  private async loop(): Promise<void> {
    while (!this.isStopped) {
      await this.delay(this.lease.renewalIntervalMs);
      if (this.isStopped) return;
      if (!(await this.renew()) && !this.lease.keepRenewingAfterFailure) return;
    }
  }

  private async renew(): Promise<boolean> {
    for (let attempt = 1; attempt <= RENEWAL_ATTEMPTS; attempt += 1) {
      try {
        await this.deps.sqs.send(
          new ChangeMessageVisibilityCommand({
            QueueUrl: this.lease.queueUrl,
            ReceiptHandle: this.lease.receiptHandle,
            VisibilityTimeout: this.lease.visibilityTimeoutSeconds,
          }),
        );
        return true;
      } catch (error) {
        if (attempt === RENEWAL_ATTEMPTS) {
          this.recordFailure(error);
          return false;
        }
        await this.delay(RENEWAL_RETRY_BASE_MS * attempt);
        if (this.isStopped) return false;
      }
    }
    return false;
  }

  private recordFailure(error: unknown): void {
    this.failure = new Error(this.lease.failureCode);
    this.deps.logger.warn('sqs_visibility_renewal_failed', {
      code: this.lease.failureCode,
      error_type: errorType(error),
    });
  }

  private async delay(ms: number): Promise<void> {
    await new Promise<void>((resolve) => {
      const handle = this.timers.setTimeout(() => {
        this.wake = undefined;
        resolve();
      }, ms);
      this.wake = () => {
        this.timers.clearTimeout(handle);
        this.wake = undefined;
        resolve();
      };
    });
  }
}
