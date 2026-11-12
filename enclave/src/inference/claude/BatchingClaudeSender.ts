import type { InferenceArmId, InferencePurpose } from '@folklore/contracts';
import type { TenantBatchConsent } from '../../directory/TenantBatchConsent.js';
import { DEFAULT_ARM } from '../InferencePurposeScope.js';
import type { CreatedMessage } from './ClaudeMessagesBackend.js';
import { BatchPendingError } from './batch-errors.js';
import { batchRunScope, type BatchRunState } from './BatchRunScope.js';
import { customIdFor, resultKeyFor, sealedResultOf } from './batch-keys.js';
import type { ClaudeRequestBody } from './claude-request.js';
import { ClaudeRouteError } from './claude-route-errors.js';

// Page work only: anything else, including a purpose added later or an unnamed one, stays synchronous.
const BATCHABLE_PURPOSES: ReadonlySet<InferencePurpose | 'untagged'> = new Set([
  'wiki_outline',
  'wiki_outline_long',
  'wiki_section',
  'wiki_section_long',
  'wiki_section_add',
  'wiki_delta',
  'wiki_revise',
  'wiki_page_revise',
  'wiki_review',
  'wiki_page_check',
  'wiki_relevance',
  'wiki_recovery',
  'wiki_repair',
  'wiki_visual_warrant',
  'wiki_visual_draw',
  'wiki_article',
  'wiki_article_long',
  'wiki_article_check',
  'wiki_critique',
  'citation_check',
]);

export interface BatchingClaudeSenderDeps {
  readonly purpose: InferencePurpose | 'untagged';
  readonly state: BatchRunState;
}

/** Replays a page run to its first miss: a sealed result is returned, a miss joins the run's pending set. */
export class BatchingClaudeSender {
  constructor(private readonly deps: BatchingClaudeSenderDeps) {}

  /** Undefined only for a miss in a drained run, whose caller then sends it itself. */
  async send(request: ClaudeRequestBody): Promise<CreatedMessage | undefined> {
    const { state } = this.deps;
    const customId = customIdFor(state.nameKey, request);
    const sealed = sealedResultOf(await state.store.get<string>(resultKeyFor(customId)));
    if (sealed?.kind === 'message') return sealed.message;
    if (sealed?.kind === 'failure') throw new ClaudeRouteError(sealed.code);
    if (state.drain === true) return undefined;
    state.pending.set(customId, { request, model: request.model, purpose: this.deps.purpose });
    throw new BatchPendingError();
  }
}

export interface BatchSendRouteDeps {
  readonly enabled: () => boolean;
  readonly consent: Pick<TenantBatchConsent, 'allows'>;
}

/** Decides per call whether a Claude request joins the open wiki request's batch. */
export class BatchSendRoute {
  constructor(private readonly deps: BatchSendRouteDeps) {}

  // A shadow arm is an experiment beside the page, so it never holds the page's batch.
  senderFor(
    orgId: string,
    purpose: InferencePurpose | 'untagged',
    arm: InferenceArmId = DEFAULT_ARM,
  ): BatchingClaudeSender | undefined {
    const state = batchRunScope.current();
    if (state === undefined || state.orgId !== orgId || arm !== DEFAULT_ARM) return undefined;
    if (!this.deps.enabled() || !BATCHABLE_PURPOSES.has(purpose)) return undefined;
    if (!this.deps.consent.allows(orgId)) return undefined;
    return new BatchingClaudeSender({ purpose, state });
  }
}
