import { INFERENCE_MODEL_CATALOG } from '@folklore/contracts';
import type { DecisionModel, InferenceUsageSink } from '@folklore/inference';
import type { AttestedSsmParameterReader } from '../../attestation/AttestedSsmParameterReader.js';
import {
  TYPESAFE_DECIDE_PATH,
  createTypeSafeTransport,
  type TypeSafeTransport,
} from '../../egress/typesafe-transport.js';
import { observeUpstreamFetch } from '../upstream-observation.js';
import type { ProviderKeyManifest } from '../credentials/AttestedProviderKeyReader.js';
import { JevQuestionGuard, type JevQuestionSet } from './JevQuestionGuard.js';
import { JEV_QUESTION_SET_DIGESTS } from './jev-question-digests.js';
import { TypeSafeCredentialSource } from './TypeSafeCredentialSource.js';
import { TypeSafeDecisionBackend } from './TypeSafeDecisionBackend.js';
import { TypeSafeDecisionError } from './typesafe-decision-errors.js';
import { mapTypeSafeTransportError } from './typesafe-error-map.js';
import type { TypeSafeDecisionRouteState } from './typesafe-decision-route-state.js';

const isDecidePost = (url: URL, init?: RequestInit): boolean =>
  (init?.method ?? 'GET').toUpperCase() === 'POST' && url.pathname === TYPESAFE_DECIDE_PATH;

type EnabledState = Extract<TypeSafeDecisionRouteState, { kind: 'enabled' }>;

export interface TypeSafeDecisionCompositionDeps {
  readonly state: TypeSafeDecisionRouteState;
  readonly questionSets: readonly JevQuestionSet[];
  readonly reader: () => Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => ProviderKeyManifest | undefined;
  readonly onAlarm: (code: string) => void;
  readonly usageSink?: InferenceUsageSink;
  readonly createTransport?: () => TypeSafeTransport;
}

/** Builds the transport and key source only on the first decision, so a disabled route never reads the key. */
export class TypeSafeDecisionComposition {
  private backend: TypeSafeDecisionBackend | undefined;

  constructor(private readonly deps: TypeSafeDecisionCompositionDeps) {}

  /** undefined while disabled; a model that always refuses while invalid. */
  model(): DecisionModel | undefined {
    const { state } = this.deps;
    if (state.kind === 'disabled') return undefined;
    if (state.kind === 'invalid') return this.refusing();
    return {
      model: INFERENCE_MODEL_CATALOG[state.model].wireModel,
      decide: async (orgId, request, options) =>
        this.backendFor(state).decide(orgId, request, options),
    };
  }

  private refusing(): DecisionModel {
    return {
      model: '',
      decide: () => Promise.reject(new TypeSafeDecisionError('typesafe_decision_route_invalid')),
    };
  }

  private backendFor(state: EnabledState): TypeSafeDecisionBackend {
    return (this.backend ??= this.build(state));
  }

  private transport(): TypeSafeTransport {
    try {
      return (this.deps.createTransport ?? createTypeSafeTransport)();
    } catch (error) {
      throw mapTypeSafeTransportError(error, { onAlarm: this.deps.onAlarm });
    }
  }

  private build(state: EnabledState): TypeSafeDecisionBackend {
    const guard = new JevQuestionGuard(this.deps.questionSets, JEV_QUESTION_SET_DIGESTS);
    const transport = this.transport();
    const credentials = new TypeSafeCredentialSource({
      reader: this.deps.reader(),
      manifest: this.deps.manifest,
      expectedBinding: state.identity.apiKeyBinding,
      transport,
      onAlarm: this.deps.onAlarm,
    });
    return new TypeSafeDecisionBackend({
      fetch: observeUpstreamFetch(transport.fetch, isDecidePost),
      credentials,
      guard,
      identity: state.identity,
      model: state.model,
      onAlarm: this.deps.onAlarm,
      ...(this.deps.usageSink === undefined ? {} : { usageSink: this.deps.usageSink }),
    });
  }
}
