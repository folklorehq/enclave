import { attestationTurnScope } from './AttestationTurnScope.js';
import {
  AdaptiveUpstreamWindow,
  UPSTREAM_WINDOW_LIMITS,
  type AdaptiveWindowLimits,
} from './AdaptiveUpstreamWindow.js';
import { NSM_ALARM_REPEAT_MS, type AttestationCapacity } from './NsmAttestationTurnstile.js';
import type { UpstreamCallAdmission, UpstreamCallGate } from './TenantPolicyBoundInference.js';
import {
  UNSCOPED_MESSAGE,
  upstreamCallScope,
  type UpstreamCallContext,
  type UpstreamCallScope,
} from './UpstreamCallScope.js';
import {
  upstreamObservationScope,
  type UpstreamCallObserver,
  type UpstreamResponseObservation,
} from './upstream-observation.js';
import { UpstreamPaceTracker } from './UpstreamPaceTracker.js';

export const ORG_WINDOW_SHARE = 0.8;
export const SYNTHESIS_RESERVED_SHARE = 0.25;
export const DEFAULT_UPSTREAM = 'default';
export const OVERLOAD_STATUSES: ReadonlySet<number> = new Set([429, 503, 529]);
export const MESSAGE_ROTATION_HISTORY_LIMIT = 1_024;
export const NSM_PASS_THROUGH_OVER_CEILING_CODE = 'nsm_pass_through_over_ceiling';

export const BACKGROUND_PRIORITY_AGE_MS = 5 * 60_000;

const NEVER_ADMITTED = -1;
const FIRST_SUCCESS_STATUS = 200;
const LAST_SUCCESS_STATUS = 299;

export interface HostUpstreamCallGateOptions {
  readonly limits?: AdaptiveWindowLimits;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly scope?: UpstreamCallScope;
  /** Absent: no NSM ceiling. */
  readonly attestationCapacity?: AttestationCapacity;
  /** Pass-through calls alone reached the NSM ceiling: on the first time, then at most once per NSM_ALARM_REPEAT_MS. */
  readonly onPassThroughOverCeiling?: () => void;
}

interface Waiter {
  readonly lane: Lane;
  readonly tenantId: string;
  readonly messageKey: string;
  readonly message: number;
  readonly background: boolean;
  readonly enqueuedAt: number;
  readonly sequence: number;
  readonly signal: AbortSignal | undefined;
  readonly admit: (ticket: Ticket) => void;
  readonly reject: (reason: unknown) => void;
}

interface Ticket {
  readonly lane: Lane;
  readonly tenantId: string;
  readonly gated: boolean;
  readonly epoch: number;
  readonly windowLimited: boolean;
}

interface SignalWaiters {
  readonly waiters: Set<Waiter>;
  readonly listener: () => void;
}

class Lane {
  readonly pace: UpstreamPaceTracker;
  readonly window: AdaptiveUpstreamWindow;
  readonly waiters: Waiter[] = [];
  readonly waitersByTenant = new Map<string, number>();
  readonly gatedByTenant = new Map<string, number>();
  readonly lastTenantAdmission = new Map<string, number>();
  readonly lastMessageAdmission = new Map<string, number>();
  active = 0;
  gatedActive = 0;
  pauseTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(limits: AdaptiveWindowLimits, now: () => number, random: () => number) {
    this.pace = new UpstreamPaceTracker(now);
    this.window = new AdaptiveUpstreamWindow(limits, now, random);
  }

  gatedFor(tenantId: string): number {
    return this.gatedByTenant.get(tenantId) ?? 0;
  }

  hasOtherWaiter(tenantId: string): boolean {
    return this.waitersByTenant.size > (this.waitersByTenant.has(tenantId) ? 1 : 0);
  }

  addWaiter(waiter: Waiter): void {
    this.waiters.push(waiter);
    this.waitersByTenant.set(waiter.tenantId, (this.waitersByTenant.get(waiter.tenantId) ?? 0) + 1);
  }

  removeWaiter(waiter: Waiter): void {
    const index = this.waiters.indexOf(waiter);
    if (index === -1) return;
    this.waiters.splice(index, 1);
    const remaining = (this.waitersByTenant.get(waiter.tenantId) ?? 0) - 1;
    if (remaining > 0) this.waitersByTenant.set(waiter.tenantId, remaining);
    else this.waitersByTenant.delete(waiter.tenantId);
  }

  // Dropping the oldest entry only turns that message into one never admitted, which already ranks first.
  recordMessageAdmission(key: string, admission: number): void {
    this.lastMessageAdmission.delete(key);
    this.lastMessageAdmission.set(key, admission);
    if (this.lastMessageAdmission.size <= MESSAGE_ROTATION_HISTORY_LIMIT) return;
    const oldest = this.lastMessageAdmission.keys().next();
    if (oldest.done !== true) this.lastMessageAdmission.delete(oldest.value);
  }

  // With nobody waiting, an admission history orders no one, so it is dropped.
  forgetRotation(): void {
    this.lastTenantAdmission.clear();
    this.lastMessageAdmission.clear();
  }
}

class CallObserver implements UpstreamCallObserver {
  lastOkRequestMs: number | undefined;
  nearLimit = false;
  promptTokens = 0;
  completionTokens = 0;

  constructor(
    private readonly ticket: Ticket,
    private readonly paused: (lane: Lane) => void,
  ) {}

  responded(observation: UpstreamResponseObservation): void {
    const { window } = this.ticket.lane;
    const { hint } = observation;
    if (OVERLOAD_STATUSES.has(observation.status) || hint?.exhausted === true) {
      window.overloaded(this.ticket.epoch, hint?.pauseMs);
    } else if (hint?.pauseMs !== undefined) {
      window.throttled(hint.pauseMs);
    }
    if (observation.status >= FIRST_SUCCESS_STATUS && observation.status <= LAST_SUCCESS_STATUS) {
      this.lastOkRequestMs = observation.requestMs;
    }
    if (hint?.nearLimit === true) this.nearLimit = true;
    this.paused(this.ticket.lane);
  }

  timedOut(): void {
    this.ticket.lane.window.slowed(this.ticket.epoch);
  }

  limitReached(pauseMs: number): void {
    this.ticket.lane.window.overloaded(this.ticket.epoch, pauseMs);
    this.paused(this.ticket.lane);
  }

  usage(promptTokens: number, completionTokens: number): void {
    this.promptTokens += promptTokens;
    this.completionTokens += completionTokens;
  }
}

/** Bounds a host's in-flight upstream calls with one adaptive window per upstream, admitting waiting tenants in rotation. */
export class HostUpstreamCallGate implements UpstreamCallGate {
  private readonly lanes = new Map<string, Lane>();
  private readonly signals = new Map<AbortSignal, SignalWaiters>();
  private readonly limits: AdaptiveWindowLimits;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly scope: UpstreamCallScope;
  private activeAll = 0;
  private passThroughActive = 0;
  private admissions = 0;
  private sequence = 0;
  private lastOverCeilingAt: number | undefined;

  constructor(private readonly options: HostUpstreamCallGateOptions = {}) {
    this.limits = options.limits ?? UPSTREAM_WINDOW_LIMITS;
    this.now = options.now ?? (() => performance.now());
    this.random = options.random ?? Math.random;
    this.scope = options.scope ?? upstreamCallScope;
    this.assertLimits(this.limits);
  }

  async run<T>(
    tenantId: string,
    call: () => Promise<T>,
    admission?: UpstreamCallAdmission,
  ): Promise<T> {
    const context = this.scope.current();
    this.assertLive(context);
    const lane = this.laneOf(admission?.upstream ?? DEFAULT_UPSTREAM);
    const message = context?.message ?? UNSCOPED_MESSAGE;
    const immediate = lane.waiters.length === 0 && this.canAdmit(lane, tenantId);
    if (immediate) return this.perform(this.take(lane, tenantId, message, true), call);
    const ticket = await this.waitForPlace(lane, tenantId, context, admission);
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (context?.signal?.aborted === true) {
      this.release(ticket);
      this.admitWaiting();
      throw context.signal.reason;
    }
    return this.perform(ticket, call);
  }

  passThrough(): UpstreamCallGate {
    return {
      run: (tenantId, call, admission) => this.runPassThrough(tenantId, call, admission),
    };
  }

  pause(upstream: string, pauseMs: number): void {
    const lane = this.laneOf(upstream);
    lane.window.throttled(pauseMs);
    this.armPauseTimer(lane);
  }

  pauseRemainingMs(upstream: string): number {
    return this.lanes.get(upstream)?.window.pauseRemainingMs() ?? 0;
  }

  activeCount(upstream?: string): number {
    return upstream === undefined ? this.activeAll : (this.lanes.get(upstream)?.active ?? 0);
  }

  pendingCount(tenantId?: string): number {
    let pending = 0;
    for (const lane of this.lanes.values()) {
      pending +=
        tenantId === undefined ? lane.waiters.length : (lane.waitersByTenant.get(tenantId) ?? 0);
    }
    return pending;
  }

  windowOf(upstream: string): number {
    return this.laneOf(upstream).window.limit;
  }

  isBacklogged(upstream: string): boolean {
    const lane = this.laneOf(upstream);
    return lane.waiters.length > lane.window.limit;
  }

  rotationHistorySize(upstream: string): number {
    return this.laneOf(upstream).lastMessageAdmission.size;
  }

  pendingUpstreamsFor(tenantId: string): readonly string[] {
    return [...this.lanes.entries()]
      .filter(([, lane]) => lane.waitersByTenant.has(tenantId))
      .map(([upstream]) => upstream);
  }

  isNsmSaturated(): boolean {
    const capacity = this.options.attestationCapacity;
    return capacity !== undefined && this.anyWaiter() && this.activeAll >= capacity.callCeiling();
  }

  private async runPassThrough<T>(
    tenantId: string,
    call: () => Promise<T>,
    admission?: UpstreamCallAdmission,
  ): Promise<T> {
    const lane = this.laneOf(admission?.upstream ?? DEFAULT_UPSTREAM);
    const ticket = this.take(lane, tenantId, UNSCOPED_MESSAGE, false);
    this.reportPassThroughOverCeiling();
    return this.perform(ticket, call, (invoke) =>
      attestationTurnScope.run({ priority: true }, invoke),
    );
  }

  private async perform<T>(
    ticket: Ticket,
    call: () => Promise<T>,
    wrap: (invoke: () => Promise<T>) => Promise<T> = (invoke) => invoke(),
  ): Promise<T> {
    const observer = new CallObserver(ticket, (lane) => this.armPauseTimer(lane));
    try {
      return await wrap(() => upstreamObservationScope.run(observer, call));
    } finally {
      this.settle(ticket, observer);
    }
  }

  private settle(ticket: Ticket, observer: CallObserver): void {
    this.release(ticket);
    const { lane } = ticket;
    if (observer.lastOkRequestMs !== undefined) {
      const cls = lane.pace.sample(
        observer.lastOkRequestMs,
        observer.promptTokens,
        observer.completionTokens,
      );
      if (cls === 'slow' && lane.window.slowed(ticket.epoch)) lane.pace.resetRecent();
      lane.window.served(ticket.windowLimited && cls === 'normal' && !observer.nearLimit);
    }
    this.admitWaiting();
    if (lane.waiters.length === 0) lane.forgetRotation();
  }

  private waitForPlace(
    lane: Lane,
    tenantId: string,
    context: UpstreamCallContext | undefined,
    admission: UpstreamCallAdmission | undefined,
  ): Promise<Ticket> {
    const message = context?.message ?? UNSCOPED_MESSAGE;
    this.sequence += 1;
    let enqueued: Waiter | undefined;
    const queued = new Promise<Ticket>((admit, reject) => {
      enqueued = {
        lane,
        tenantId,
        messageKey: this.messageKey(tenantId, message),
        message,
        background: context?.background === true,
        enqueuedAt: this.now(),
        sequence: this.sequence,
        signal: context?.signal,
        admit,
        reject,
      };
      lane.addWaiter(enqueued);
      this.watchAbort(enqueued);
    });
    // The caller awaits this promise; a rejection raised before it does so must not surface as unhandled.
    queued.catch(() => undefined);
    const waiter = enqueued;
    if (admission?.onWait === undefined || waiter === undefined) return queued;
    return this.awaitThrough(admission.onWait, queued, waiter);
  }

  private async awaitThrough(
    onWait: (wait: () => Promise<void>) => Promise<void>,
    queued: Promise<Ticket>,
    waiter: Waiter,
  ): Promise<Ticket> {
    let ticket: Ticket | undefined;
    try {
      await onWait(async () => {
        ticket = await queued;
      });
    } catch (error) {
      this.abandonWait(waiter, queued);
      throw error;
    }
    return ticket ?? queued;
  }

  // An onWait that threw leaves nobody to run the call, so a taken place is released and a pending one withdrawn.
  private abandonWait(waiter: Waiter, queued: Promise<Ticket>): void {
    if (waiter.lane.waiters.includes(waiter)) {
      waiter.lane.removeWaiter(waiter);
      this.unwatchAbort(waiter);
      if (waiter.lane.waiters.length === 0) waiter.lane.forgetRotation();
      this.admitWaiting();
      return;
    }
    void queued.then(
      (ticket) => {
        this.release(ticket);
        this.admitWaiting();
      },
      () => undefined,
    );
  }

  private watchAbort(waiter: Waiter): void {
    const { signal } = waiter;
    if (signal === undefined) return;
    let entry = this.signals.get(signal);
    if (entry === undefined) {
      const listener = () => this.abortWaiters(signal);
      entry = { waiters: new Set(), listener };
      this.signals.set(signal, entry);
      signal.addEventListener('abort', listener, { once: true });
    }
    entry.waiters.add(waiter);
  }

  private unwatchAbort(waiter: Waiter): void {
    const { signal } = waiter;
    const entry = signal === undefined ? undefined : this.signals.get(signal);
    if (signal === undefined || entry === undefined) return;
    entry.waiters.delete(waiter);
    if (entry.waiters.size > 0) return;
    signal.removeEventListener('abort', entry.listener);
    this.signals.delete(signal);
  }

  private abortWaiters(signal: AbortSignal): void {
    const entry = this.signals.get(signal);
    if (entry === undefined) return;
    this.signals.delete(signal);
    for (const waiter of entry.waiters) {
      waiter.lane.removeWaiter(waiter);
      waiter.reject(signal.reason);
    }
    this.admitWaiting();
  }

  private admitWaiting(): void {
    const lanes = [...this.lanes.values()]
      .filter((lane) => lane.waiters.length > 0)
      .sort((left, right) => this.oldestSequence(left) - this.oldestSequence(right));
    for (const lane of lanes) {
      while (this.withinCeiling()) {
        const waiter = this.nextWaiter(lane);
        if (waiter === undefined) break;
        this.admitWaiter(waiter);
      }
      if (!this.withinCeiling()) return;
    }
  }

  private admitWaiter(waiter: Waiter): void {
    waiter.lane.removeWaiter(waiter);
    this.unwatchAbort(waiter);
    waiter.admit(this.take(waiter.lane, waiter.tenantId, waiter.message, true));
  }

  // Tenant, then synthesis before queue jobs until a job has waited BACKGROUND_PRIORITY_AGE_MS, then least recently admitted message, then FIFO.
  private nextWaiter(lane: Lane): Waiter | undefined {
    const eligible = new Map<string, boolean>();
    const at = this.now();
    let next: Waiter | undefined;
    let nextDeferred = false;
    let tenantAt = Number.POSITIVE_INFINITY;
    let messageAt = Number.POSITIVE_INFINITY;
    for (const waiter of lane.waiters) {
      const allowed = eligible.get(waiter.tenantId) ?? this.canAdmit(lane, waiter.tenantId);
      eligible.set(waiter.tenantId, allowed);
      if (!allowed) continue;
      const waiterTenantAt = lane.lastTenantAdmission.get(waiter.tenantId) ?? NEVER_ADMITTED;
      const waiterMessageAt = lane.lastMessageAdmission.get(waiter.messageKey) ?? NEVER_ADMITTED;
      const deferred = waiter.background && at - waiter.enqueuedAt < BACKGROUND_PRIORITY_AGE_MS;
      const tenantIsNext = waiterTenantAt < tenantAt;
      const sameTenant = waiterTenantAt === tenantAt && waiter.tenantId === next?.tenantId;
      const sameTenantBetter =
        sameTenant && (nextDeferred === deferred ? waiterMessageAt < messageAt : nextDeferred);
      if (!tenantIsNext && !sameTenantBetter) continue;
      next = waiter;
      nextDeferred = deferred;
      tenantAt = waiterTenantAt;
      messageAt = waiterMessageAt;
    }
    return next;
  }

  private canAdmit(lane: Lane, tenantId: string): boolean {
    return this.withinCeiling() && this.laneAllows(lane, tenantId);
  }

  private withinCeiling(): boolean {
    const capacity = this.options.attestationCapacity;
    return capacity === undefined || this.activeAll < capacity.callCeiling();
  }

  private laneAllows(lane: Lane, tenantId: string): boolean {
    if (lane.window.pauseRemainingMs() > 0) return false;
    const limit = lane.window.limit;
    const underReserve =
      lane.gatedActive < Math.max(1, Math.floor(limit * SYNTHESIS_RESERVED_SHARE));
    if (lane.active >= limit && !underReserve) return false;
    const share = Math.max(1, Math.floor(limit * ORG_WINDOW_SHARE));
    return lane.gatedFor(tenantId) < share || !lane.hasOtherWaiter(tenantId);
  }

  private take(lane: Lane, tenantId: string, message: number, gated: boolean): Ticket {
    const ticket: Ticket = {
      lane,
      tenantId,
      gated,
      epoch: lane.window.epoch,
      windowLimited: lane.active + 1 >= lane.window.limit,
    };
    lane.active += 1;
    this.activeAll += 1;
    if (!gated) {
      this.passThroughActive += 1;
      return ticket;
    }
    lane.gatedActive += 1;
    lane.gatedByTenant.set(tenantId, lane.gatedFor(tenantId) + 1);
    this.admissions += 1;
    lane.lastTenantAdmission.set(tenantId, this.admissions);
    lane.recordMessageAdmission(this.messageKey(tenantId, message), this.admissions);
    return ticket;
  }

  private release(ticket: Ticket): void {
    const { lane, tenantId } = ticket;
    lane.active -= 1;
    this.activeAll -= 1;
    if (!ticket.gated) {
      this.passThroughActive -= 1;
      return;
    }
    lane.gatedActive -= 1;
    const remaining = lane.gatedFor(tenantId) - 1;
    if (remaining > 0) lane.gatedByTenant.set(tenantId, remaining);
    else lane.gatedByTenant.delete(tenantId);
  }

  private armPauseTimer(lane: Lane): void {
    const remaining = lane.window.pauseRemainingMs();
    if (remaining <= 0) return;
    if (lane.pauseTimer !== undefined) clearTimeout(lane.pauseTimer);
    lane.pauseTimer = setTimeout(() => {
      lane.pauseTimer = undefined;
      this.armPauseTimer(lane);
      this.admitWaiting();
    }, remaining);
    lane.pauseTimer.unref?.();
  }

  private reportPassThroughOverCeiling(): void {
    const capacity = this.options.attestationCapacity;
    if (capacity === undefined || this.passThroughActive < capacity.callCeiling()) return;
    const at = this.now();
    if (this.lastOverCeilingAt !== undefined && at - this.lastOverCeilingAt < NSM_ALARM_REPEAT_MS) {
      return;
    }
    this.lastOverCeilingAt = at;
    this.options.onPassThroughOverCeiling?.();
  }

  private assertLive(context: UpstreamCallContext | undefined): void {
    if (context?.signal?.aborted === true) throw context.signal.reason;
  }

  private anyWaiter(): boolean {
    for (const lane of this.lanes.values()) if (lane.waiters.length > 0) return true;
    return false;
  }

  private oldestSequence(lane: Lane): number {
    return lane.waiters[0]?.sequence ?? Number.POSITIVE_INFINITY;
  }

  private laneOf(upstream: string): Lane {
    let lane = this.lanes.get(upstream);
    if (lane === undefined) {
      lane = new Lane(this.limits, this.now, this.random);
      this.lanes.set(upstream, lane);
    }
    return lane;
  }

  private messageKey(tenantId: string, message: number): string {
    return `${tenantId}\u0000${message}`;
  }

  private assertLimits(limits: AdaptiveWindowLimits): void {
    const valid = [limits.initial, limits.floor, limits.ceiling].every(
      (value) => Number.isSafeInteger(value) && value > 0,
    );
    if (!valid || limits.floor > limits.initial || limits.initial > limits.ceiling) {
      throw new RangeError('upstream_call_limits_invalid');
    }
  }
}
