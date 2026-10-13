import type { PullDueMessage } from '../../pull/pull-runner.js';
import type { QueueAssignment } from '../QueueSetDrainer.js';

export interface PendingContinuation {
  assignment: QueueAssignment;
  message: PullDueMessage;
}

/** The next chunk owed per tenant source, recorded only after the previous chunk was durably acked. */
export class PullContinuations {
  private readonly pending = new Map<string, PendingContinuation>();

  record(assignment: QueueAssignment, message: PullDueMessage): void {
    this.pending.set(`${assignment.tenantId}\0${message.sourceId}`, { assignment, message });
  }

  takeAll(): PendingContinuation[] {
    const taken = [...this.pending.values()];
    this.pending.clear();
    return taken;
  }
}
