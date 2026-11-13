import {
  DECISION_SITE_PURPOSE,
  INFERENCE_MODEL_CATALOG,
  type InferenceModelId,
} from '@folklore/contracts';
import type {
  DecideOptions,
  DecisionModel,
  DecisionRequest,
  DecisionResult,
  InferenceUsageSink,
} from '@folklore/inference';
import { sha256Hex } from '@folklore/utils';
import { TYPESAFE_DECIDE_PATH, TYPESAFE_ORIGIN } from '../../egress/typesafe-transport.js';
import { readBoundedText } from '../bounded-response-body.js';
import type { JevQuestionGuard } from './JevQuestionGuard.js';
import type { TypeSafeCredentialSource } from './TypeSafeCredentialSource.js';
import type { TypeSafeDecisionRouteIdentity } from './typesafe-decision-route-config.js';
import { TypeSafeDecisionError } from './typesafe-decision-errors.js';
import { mapTypeSafeStatus, mapTypeSafeTransportError } from './typesafe-error-map.js';
import { parseJevResponse } from './jev-response.js';

export const JEV_MAX_QUESTION_TOKENS = 32_000;
export const JEV_MAX_REQUEST_TOKENS = 64_000;
export const JEV_BYTES_PER_TOKEN_FLOOR = 3;
export const JEV_LIMIT_HEADROOM = 0.9;
export const JEV_DEFAULT_TIMEOUT_MS = 15_000;

const JEV_RESPONSE_BODY_MAX_BYTES = 262_144;
const USER_AGENT = 'folklore-enclave';

export interface TypeSafeDecisionBackendDeps {
  readonly fetch: typeof globalThis.fetch;
  readonly credentials: Pick<TypeSafeCredentialSource, 'key' | 'invalidate'>;
  readonly guard: JevQuestionGuard;
  readonly identity: TypeSafeDecisionRouteIdentity;
  readonly model: InferenceModelId;
  readonly usageSink?: InferenceUsageSink;
  readonly onAlarm?: (code: string) => void;
}

/** One decision call per request, admitted by org scope and registered questions before anything is sent. */
export class TypeSafeDecisionBackend implements DecisionModel {
  readonly model: string;

  constructor(private readonly deps: TypeSafeDecisionBackendDeps) {
    this.model = INFERENCE_MODEL_CATALOG[deps.model].wireModel;
  }

  async decide(
    orgId: string,
    request: DecisionRequest,
    options?: DecideOptions,
  ): Promise<DecisionResult> {
    options?.signal?.throwIfAborted();
    this.assertInScope(orgId);
    const questions = this.deps.guard.assertRegistered(request);
    const body = this.bodyOf(request.state, questions);
    try {
      const key = await this.deps.credentials.key();
      const response = await this.post(body, key, options);
      return await this.resultFrom(response, request, questions, options);
    } catch (error) {
      options?.signal?.throwIfAborted();
      throw mapTypeSafeTransportError(error, this.alarm());
    }
  }

  private assertInScope(orgId: string): void {
    const { identity } = this.deps;
    if (!identity.enabled) throw new TypeSafeDecisionError('typesafe_decision_route_invalid');
    if (identity.orgScope === 'own_org' && !identity.orgIdSha256s.includes(sha256Hex(orgId))) {
      throw new TypeSafeDecisionError('typesafe_org_out_of_scope');
    }
  }

  private bodyOf(state: DecisionRequest['state'], questions: DecisionRequest['questions']): string {
    const body = JSON.stringify({ model: this.model, state, questions });
    const stateBytes = Buffer.byteLength(JSON.stringify(state));
    const questionTooLarge = Object.values(questions).some(
      (question) =>
        this.tokens(stateBytes + Buffer.byteLength(JSON.stringify(question))) >
        JEV_MAX_QUESTION_TOKENS * JEV_LIMIT_HEADROOM,
    );
    if (
      questionTooLarge ||
      this.tokens(Buffer.byteLength(body)) > JEV_MAX_REQUEST_TOKENS * JEV_LIMIT_HEADROOM
    ) {
      throw new TypeSafeDecisionError('typesafe_request_too_large', undefined, true);
    }
    return body;
  }

  private tokens(bytes: number): number {
    return bytes / JEV_BYTES_PER_TOKEN_FLOOR;
  }

  private post(body: string, key: string, options?: DecideOptions): Promise<Response> {
    const timeout = AbortSignal.timeout(options?.timeoutMs ?? JEV_DEFAULT_TIMEOUT_MS);
    return this.deps.fetch(`${TYPESAFE_ORIGIN}${TYPESAFE_DECIDE_PATH}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${key}`,
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': USER_AGENT,
      },
      body,
      signal: options?.signal === undefined ? timeout : AbortSignal.any([timeout, options.signal]),
    });
  }

  private async resultFrom(
    response: Response,
    request: DecisionRequest,
    questions: DecisionRequest['questions'],
    options?: DecideOptions,
  ): Promise<DecisionResult> {
    if (!response.ok) throw await this.statusFailure(response);
    const text = await readBoundedText(response, JEV_RESPONSE_BODY_MAX_BYTES).catch(() => {
      throw new TypeSafeDecisionError('typesafe_response_invalid');
    });
    return parseJevResponse(text, questions, this.model, (promptTokens, completionTokens) =>
      this.recordUsage(request, promptTokens, completionTokens, options),
    );
  }

  private statusFailure(response: Response): Promise<TypeSafeDecisionError> {
    return mapTypeSafeStatus(response, {
      onCredentialRejected: () => this.deps.credentials.invalidate('rejected'),
      ...this.alarm(),
    });
  }

  private recordUsage(
    request: DecisionRequest,
    promptTokens: number,
    completionTokens: number,
    options?: DecideOptions,
  ): void {
    this.deps.usageSink?.({
      model: this.model,
      operation: 'structured',
      promptTokens,
      completionTokens,
      cached: false,
      purpose: DECISION_SITE_PURPOSE[request.sites[0]],
      ...(options?.outcome === undefined ? {} : { outcome: options.outcome }),
    });
  }

  private alarm(): { readonly onAlarm?: (code: string) => void } {
    const { onAlarm } = this.deps;
    return onAlarm === undefined ? {} : { onAlarm };
  }
}
