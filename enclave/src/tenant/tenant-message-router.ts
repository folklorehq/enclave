import type { SSMClient } from '@aws-sdk/client-ssm';
import { decryptPayload, type EncryptedPayload } from '../ingest/receiver.js';
import type { ProcessedFact } from '../pipeline/index.js';
import {
  buildPullCompleteSignal,
  runPull,
  type PullCompleteSignal,
  type PullDueMessage,
} from '../pull/pull-runner.js';
import type { TenantContext } from './tenant-context.js';
import type { TenantRegistry } from './tenant-registry.js';

export interface IngestMessage {
  tenant_id: string;
  source: string;
  eventType?: string;
  type?: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

export type RoutableMessage = IngestMessage | PullDueMessage;

export interface RoutedResult {
  context: TenantContext;
  facts: ProcessedFact[];
  pullComplete?: PullCompleteSignal;
}

export interface TenantMessageRouterDeps {
  registry: TenantRegistry;
  ssm: SSMClient;
  controlPlaneUrl: string;
  deploymentId: string;
  agentToken: () => string;
}

// A message arrived on a queue owned by one tenant but its body names a different one — the two
// authorities disagree, so it is poison, never processed. Content-free: only tenant ids (ADL #18).
export class CrossTenantRoutingError extends Error {
  constructor(
    readonly queueTenantId: string,
    readonly messageTenantId: string,
  ) {
    super(`message for ${messageTenantId} arrived on ${queueTenantId}'s queue`);
    this.name = 'CrossTenantRoutingError';
  }
}

function isPullDueMessage(raw: RoutableMessage): raw is PullDueMessage {
  return raw.type === 'pull-due';
}

// Resolves a message to its tenant's isolated context and processes it there (design §2.2/§2.3).
// The queue's owning tenant is authoritative: routing keys off `queueTenantId`, never off the
// message body, and a body naming a different tenant is rejected before any keyring is touched —
// so a relabelled ciphertext can never select another tenant's ingest key or pipeline.
export class TenantMessageRouter {
  constructor(private readonly deps: TenantMessageRouterDeps) {}

  async route(raw: RoutableMessage, queueTenantId: string): Promise<RoutedResult> {
    if (raw.tenant_id !== queueTenantId) {
      throw new CrossTenantRoutingError(queueTenantId, raw.tenant_id);
    }
    const context = this.deps.registry.get(queueTenantId);

    if (isPullDueMessage(raw)) {
      const facts = await runPull(raw, {
        ssm: this.deps.ssm,
        privateKey: context.ingestPrivateKey,
        controlPlaneUrl: this.deps.controlPlaneUrl,
        deploymentId: this.deps.deploymentId,
        agentToken: this.deps.agentToken(),
        pipeline: context.pipeline,
      });
      return { context, facts, pullComplete: buildPullCompleteSignal(raw) };
    }

    const payload: EncryptedPayload = {
      ephemeralPublicKey: raw.ephemeralPublicKey,
      nonce: raw.nonce,
      ciphertext: raw.ciphertext,
    };
    const plaintext = decryptPayload(payload, context.ingestPrivateKey);
    const facts =
      raw.type === 'pull-normalized'
        ? await context.pipeline.handleNormalized(plaintext, raw.source)
        : await context.pipeline.handle(plaintext, raw.source, raw.eventType ?? '');
    return { context, facts };
  }
}
