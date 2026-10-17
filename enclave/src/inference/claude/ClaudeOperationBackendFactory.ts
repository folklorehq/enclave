import {
  GenerationContextFloorError,
  type InferenceModelRole,
  type InferenceUsageSink,
  type VerifiedActivePolicyRoleBindingV1,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import type { AnthropicTransport } from '../../egress/anthropic-transport.js';
import { inferencePurposeScope } from '../InferencePurposeScope.js';
import type { OperationAdmission, OperationAuthority } from '../OperationAuthority.js';
import type { TenantPolicyOperationBackend } from '../TenantPolicyBoundInference.js';
import { recordTokenUsage } from '../TokenUsageScope.js';
import { observeUpstreamFetch } from '../upstream-observation.js';
import type { ClaudeCredentialSource } from './ClaudeCredentialSource.js';
import { ClaudeMessagesBackend } from './ClaudeMessagesBackend.js';
import { ClaudeRouteError } from './claude-route-errors.js';
import { mapClaudeError, type ClaudeErrorContext } from './claude-error-map.js';
import { CLAUDE_OPERATION_DEADLINE } from './claude-outage-scope.js';
import { claudeTimeoutMs } from './claude-purpose-limits.js';
import {
  UPSTREAM_KEY_PREFIX,
  type ClaudeRoute,
  type InferenceRouteResolver,
} from './InferenceRouteResolver.js';

const MESSAGES_PATH = '/v1/messages';
const HIGH_WATER_STALE = 'claude_high_water_stale';
const HIGH_WATER_UNAVAILABLE = 'claude_high_water_unavailable';
const MOVED_HEAD_PREFIX = 'active_policy_';
const MOVED_HEAD_MESSAGES: ReadonlySet<string> = new Set(['checkpoint_not_pinned']);

export type ClaudeRouteBackendFactory = (
  binding: VerifiedActivePolicyRoleBindingV1,
  snapshot: VerifiedActivePolicySnapshotV1,
  route: ClaudeRoute,
) => Promise<TenantPolicyOperationBackend>;

export interface ClaudeOperationBackendFactoryDeps {
  readonly resolver: InferenceRouteResolver;
  readonly authority: OperationAuthority;
  readonly credentials: () => ClaudeCredentialSource;
  readonly transport: () => AnthropicTransport;
  readonly usageSink?: InferenceUsageSink;
  readonly onAlarm?: (code: string) => void;
}

const isMovedHead = (error: unknown): boolean =>
  error instanceof GenerationContextFloorError ||
  (error instanceof Error &&
    (error.message.startsWith(MOVED_HEAD_PREFIX) || MOVED_HEAD_MESSAGES.has(error.message)));

const isMessagesPost = (url: URL, init?: RequestInit): boolean =>
  (init?.method ?? 'GET').toUpperCase() === 'POST' && url.pathname === MESSAGES_PATH;

export function createClaudeOperationBackendFactory(
  deps: ClaudeOperationBackendFactoryDeps,
): ClaudeRouteBackendFactory {
  return async (binding, snapshot, route) => {
    if (!deps.resolver.enabled) throw new ClaudeRouteError('claude_route_disabled');
    if (!deps.resolver.allowedModels().includes(route.model)) {
      throw new ClaudeRouteError('claude_model_not_allowed');
    }
    const admission = await deps.authority.admit(binding, snapshot);
    return new ClaudeOperation(deps, binding, route, admission).backend();
  };
}

class ClaudeOperation {
  private consumed = false;
  private readonly errorContext: ClaudeErrorContext;
  private credentials: ClaudeCredentialSource | undefined;

  constructor(
    private readonly deps: ClaudeOperationBackendFactoryDeps,
    private readonly binding: VerifiedActivePolicyRoleBindingV1,
    private readonly route: ClaudeRoute,
    private readonly admission: OperationAdmission,
  ) {
    this.errorContext = {
      upstream: `${UPSTREAM_KEY_PREFIX}${route.model}`,
      budgetExpired: () => this.budgetExpired(),
      onCredentialRejected: () => this.credentialSource().invalidate('rejected'),
      ...(deps.onAlarm === undefined ? {} : { onAlarm: deps.onAlarm }),
    };
  }

  backend(): TenantPolicyOperationBackend {
    return {
      embed: () => Promise.reject(new ClaudeRouteError('claude_embed_unsupported')),
      generate: (prompt, systemPrompt) =>
        this.invoke('generate', (backend) => backend.generate(prompt, systemPrompt)),
      critique: (prompt, systemPrompt) =>
        this.invoke('critique', (backend) => backend.critique(prompt, systemPrompt)),
      generateStructured: (prompt, tool, systemPrompt) =>
        this.invoke('judge', (backend) => backend.generateStructured(prompt, tool, systemPrompt)),
    };
  }

  private async invoke<T>(
    role: InferenceModelRole,
    call: (backend: ClaudeMessagesBackend) => Promise<T>,
  ): Promise<T> {
    if (this.consumed) throw new ClaudeRouteError('claude_operation_consumed');
    this.consumed = true;
    try {
      if (this.binding.role !== role) throw new ClaudeRouteError('claude_operation_role_mismatch');
      const apiKey = await this.withinBudget(this.credentialSource().key());
      await this.admission.trustedTime.read(this.admission.trustedTimeContext);
      await this.withinBudget(this.assertPinned());
      this.remainingBudget();
      const result = await call(this.messagesBackend(apiKey));
      this.remainingBudget();
      return result;
    } catch (error) {
      throw mapClaudeError(error, this.errorContext);
    }
  }

  private messagesBackend(apiKey: string): ClaudeMessagesBackend {
    const credentials = this.credentialSource();
    const observed = observeUpstreamFetch(this.deps.transport().fetch, isMessagesPost);
    const prefix = inferencePurposeScope.current()?.cachedSystemPrefix;
    return new ClaudeMessagesBackend({
      route: this.route,
      apiKey,
      fetch: (input, init) => observed(input, { ...init, signal: this.withDeadline(init?.signal) }),
      timeoutMs: claudeTimeoutMs(this.route.purpose, this.route.model),
      expected: this.deps.resolver.expectedIdentity(),
      usageSink: this.deps.usageSink ?? recordTokenUsage,
      errorContext: this.errorContext,
      onIdentityMismatch: () => credentials.invalidate('mismatch'),
      ...(prefix === undefined ? {} : { cachedSystemPrefix: prefix }),
    });
  }

  private async assertPinned(): Promise<void> {
    const { authority, trustedTimeContext } = this.admission;
    await authority.assertPinned(trustedTimeContext).catch((error: unknown) => {
      throw new ClaudeRouteError(isMovedHead(error) ? HIGH_WATER_STALE : HIGH_WATER_UNAVAILABLE);
    });
  }

  private withinBudget<T>(work: Promise<T>): Promise<T> {
    const deadline = AbortSignal.timeout(this.remainingBudget());
    return new Promise<T>((resolve, reject) => {
      const expire = (): void => reject(new ClaudeRouteError(CLAUDE_OPERATION_DEADLINE));
      deadline.addEventListener('abort', expire, { once: true });
      work.finally(() => deadline.removeEventListener('abort', expire)).then(resolve, reject);
    });
  }

  private withDeadline(signal: AbortSignal | null | undefined): AbortSignal {
    const deadline = AbortSignal.timeout(this.remainingBudget());
    return signal ? AbortSignal.any([signal, deadline]) : deadline;
  }

  private credentialSource(): ClaudeCredentialSource {
    return (this.credentials ??= this.deps.credentials());
  }

  private remainingBudget(): number {
    try {
      return this.admission.remainingBudget();
    } catch {
      throw new ClaudeRouteError(CLAUDE_OPERATION_DEADLINE);
    }
  }

  private budgetExpired(): boolean {
    try {
      this.admission.remainingBudget();
      return false;
    } catch {
      return true;
    }
  }
}
