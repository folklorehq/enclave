import { DEFAULT_UPSTREAM, type HostUpstreamCallGate } from './HostUpstreamCallGate.js';
import type { DeadlineBudget } from '../ingest/PausableDeadline.js';
import type { UpstreamCallAdmission, UpstreamCallGate } from './TenantPolicyBoundInference.js';
import { upstreamCallScope, type UpstreamCallScope } from './UpstreamCallScope.js';

export const GATE_WAIT_STALLED_CODE = 'upstream_gate_wait_stalled';
// Three times a message's own budget: a queue this long is a lost wake-up, not a busy host.
export const MAX_GATE_WAIT_MS = 90 * 60_000;

export class UpstreamGateWaitStalledError extends Error {
  constructor() {
    super(GATE_WAIT_STALLED_CODE);
    this.name = 'UpstreamGateWaitStalledError';
  }
}

export interface BackgroundAwareUpstreamGateOptions {
  readonly maxWaitMs?: number;
  readonly onWaitStalled?: () => void;
}

interface StallTimer {
  readonly expired: Promise<never>;
  cancel(): void;
}

/** Calls of a queue job wait in the host gate; every other call keeps its pass-through. */
export class BackgroundAwareUpstreamGate implements UpstreamCallGate {
  constructor(
    private readonly gate: Pick<HostUpstreamCallGate, 'run' | 'passThrough'>,
    private readonly scope: UpstreamCallScope = upstreamCallScope,
    private readonly options: BackgroundAwareUpstreamGateOptions = {},
  ) {}

  run<T>(tenantId: string, call: () => Promise<T>, admission?: UpstreamCallAdmission): Promise<T> {
    const context = this.scope.current();
    if (context?.background !== true) {
      return this.gate.passThrough().run(tenantId, call, admission);
    }
    return this.gate.run(tenantId, call, this.guardedWait(admission, context.waitBudget));
  }

  private guardedWait(
    admission: UpstreamCallAdmission | undefined,
    budget: DeadlineBudget | undefined,
  ): UpstreamCallAdmission {
    return {
      upstream: admission?.upstream ?? DEFAULT_UPSTREAM,
      onWait: async (wait) => {
        let stall: StallTimer | undefined;
        budget?.pause();
        try {
          stall = this.startStallTimer();
          const waiting = admission?.onWait ? admission.onWait(wait) : wait();
          waiting.catch(() => undefined);
          await Promise.race([waiting, stall.expired]);
        } finally {
          stall?.cancel();
          budget?.resume();
        }
      },
    };
  }

  private startStallTimer(): StallTimer {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        this.options.onWaitStalled?.();
        reject(new UpstreamGateWaitStalledError());
      }, this.options.maxWaitMs ?? MAX_GATE_WAIT_MS);
    });
    expired.catch(() => undefined);
    return { expired, cancel: () => clearTimeout(timer) };
  }
}
