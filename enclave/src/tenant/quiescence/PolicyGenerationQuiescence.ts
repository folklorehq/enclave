import type { Logger } from '@folklore/core';
import type { TenantEviction } from './tenant-generation-quiescence.js';

export type OnLateTenantQuiesced = (tenantId: string, attempt: number) => void;

export interface PolicyGenerationQuiescenceOptions {
  readonly quiesceWork: TenantEviction | undefined;
  readonly quiesceRequests: TenantEviction | undefined;
  readonly workTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly logger: Logger;
}

type QuiescencePhase = 'work' | 'requests';
type RunStatus = 'completed' | 'timeout' | 'rejected';

interface BoundedRun {
  readonly tenantId: string;
  readonly attempt: number;
  readonly status: RunStatus;
  readonly outcome: Promise<boolean>;
}

const QUIESCE_FAILED = 'assignment_manifest_generation_quiesce_failed';
const TIMED_OUT = 'timeout';

/** Bounded two-phase quiescence of a policy generation's tenants, remembering any that overran. */
export class PolicyGenerationQuiescence {
  private readonly late = new Map<string, Promise<boolean>>();
  private readonly attempts = new Map<string, number>();

  constructor(private readonly options: PolicyGenerationQuiescenceOptions) {}

  attemptOf(tenantId: string): number {
    return this.attempts.get(tenantId) ?? 0;
  }

  // An overrun from an earlier apply gets one more bounded wait; refused before anything is built or fenced.
  async settleLate(): Promise<void> {
    const pending = [...this.late.entries()];
    const settled = await Promise.all(
      pending.map(([, outcome]) => this.within(outcome, this.options.requestTimeoutMs)),
    );
    const stillLate = pending.filter((_, index) => settled[index] === TIMED_OUT);
    for (const [tenantId] of stillLate) {
      this.options.logger.error('tenant generation quiesce pending', { tenant_id: tenantId });
    }
    if (stillLate.length > 0) throw new Error(QUIESCE_FAILED);
  }

  // Runs unfenced, before any staged context is built, so requests keep flowing while queue work stops.
  async quiesceWork(
    tenantIds: readonly string[],
    quiesced: Set<string>,
    onLateQuiesced: OnLateTenantQuiesced,
  ): Promise<void> {
    const { quiesceWork, workTimeoutMs } = this.options;
    await this.runPhase('work', quiesceWork, workTimeoutMs, tenantIds, quiesced, onLateQuiesced);
  }

  async quiesceRequests(
    tenantIds: readonly string[],
    quiesced: Set<string>,
    onLateQuiesced: OnLateTenantQuiesced,
  ): Promise<void> {
    const { quiesceRequests, requestTimeoutMs } = this.options;
    await this.runPhase(
      'requests',
      quiesceRequests,
      requestTimeoutMs,
      tenantIds,
      quiesced,
      onLateQuiesced,
    );
  }

  private async runPhase(
    phase: QuiescencePhase,
    hook: TenantEviction | undefined,
    timeoutMs: number,
    tenantIds: readonly string[],
    quiesced: Set<string>,
    onLateQuiesced: OnLateTenantQuiesced,
  ): Promise<void> {
    const runs = await Promise.all(
      tenantIds.map((tenantId) => this.runBounded(hook, tenantId, timeoutMs)),
    );
    for (const run of runs) {
      if (run.status === 'completed') {
        quiesced.add(run.tenantId);
        continue;
      }
      quiesced.delete(run.tenantId);
      this.trackLate(run, onLateQuiesced);
      this.options.logger.error('tenant generation quiesce failed', {
        tenant_id: run.tenantId,
        phase,
        outcome: run.status,
      });
    }
    if (runs.some(({ status }) => status !== 'completed')) throw new Error(QUIESCE_FAILED);
  }

  private async runBounded(
    hook: TenantEviction | undefined,
    tenantId: string,
    timeoutMs: number,
  ): Promise<BoundedRun> {
    if (!hook) {
      return {
        tenantId,
        attempt: this.attemptOf(tenantId),
        status: 'completed',
        outcome: Promise.resolve(true),
      };
    }
    const attempt = this.attemptOf(tenantId) + 1;
    this.attempts.set(tenantId, attempt);
    const outcome = Promise.resolve()
      .then(() => hook(tenantId))
      .then(
        () => true,
        () => false,
      );
    const result = await this.within(outcome, timeoutMs);
    return { tenantId, attempt, status: this.statusOf(result), outcome };
  }

  private statusOf(result: boolean | typeof TIMED_OUT): RunStatus {
    if (result === TIMED_OUT) return 'timeout';
    return result ? 'completed' : 'rejected';
  }

  private trackLate(run: BoundedRun, onLateQuiesced: OnLateTenantQuiesced): void {
    const { tenantId, attempt, outcome } = run;
    this.late.set(tenantId, outcome);
    void outcome.then((succeeded) => {
      this.late.delete(tenantId);
      if (succeeded) onLateQuiesced(tenantId, attempt);
    });
  }

  private async within<T>(outcome: Promise<T>, timeoutMs: number): Promise<T | typeof TIMED_OUT> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMED_OUT), timeoutMs);
    });
    try {
      return await Promise.race([outcome, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
