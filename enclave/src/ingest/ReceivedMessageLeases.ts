import type { Message } from '@aws-sdk/client-sqs';
import { VisibilityHeartbeat, type VisibilityHeartbeatDeps } from './VisibilityHeartbeat.js';

export interface ReceivedMessageLeaseSettings {
  visibilityTimeoutSeconds: number;
  renewalIntervalMs: number;
  failureCode: string;
}

interface HeldLease {
  receiptHandle: string;
  heartbeat: VisibilityHeartbeat;
}

/** Keeps every received message leased until released, following its newest receipt handle. */
export class ReceivedMessageLeases {
  private readonly held = new Map<string, HeldLease>();

  constructor(
    private readonly deps: VisibilityHeartbeatDeps,
    private readonly settings: ReceivedMessageLeaseSettings,
  ) {}

  // A redelivery of a held message only moves its lease to the fresh handle; false means do not re-handle.
  async admit(queueUrl: string, msg: Message): Promise<boolean> {
    const key = this.key(msg);
    if (!key || !msg.ReceiptHandle) return true;
    const existing = this.held.get(key);
    await existing?.heartbeat.stop();
    this.held.set(key, {
      receiptHandle: msg.ReceiptHandle,
      heartbeat: this.startHeartbeat(queueUrl, msg.ReceiptHandle),
    });
    return existing === undefined;
  }

  /** Stops renewing and returns the newest receipt handle, which is the one a delete must use. */
  async release(msg: Message): Promise<string | undefined> {
    const key = this.key(msg);
    const lease = key ? this.held.get(key) : undefined;
    if (!key || !lease) return msg.ReceiptHandle;
    this.held.delete(key);
    await lease.heartbeat.stop();
    return lease.receiptHandle;
  }

  async releaseAll(): Promise<void> {
    const leases = [...this.held.values()];
    this.held.clear();
    await Promise.all(leases.map((lease) => lease.heartbeat.stop()));
  }

  private startHeartbeat(queueUrl: string, receiptHandle: string): VisibilityHeartbeat {
    const heartbeat = new VisibilityHeartbeat(this.deps, {
      queueUrl,
      receiptHandle,
      ...this.settings,
      keepRenewingAfterFailure: true,
    });
    heartbeat.start();
    return heartbeat;
  }

  private key(msg: Message): string | undefined {
    return msg.MessageId ?? msg.ReceiptHandle;
  }
}
