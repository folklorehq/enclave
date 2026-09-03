import type { SSMClient } from '@aws-sdk/client-ssm';
import type { S3Client } from '@aws-sdk/client-s3';
import { createHash } from 'node:crypto';
import {
  canaryAuthorizationOutcomeProofPayload,
  canaryPipelineOutcomePayload,
  canaryAuthorizationProofPayload,
  type CanaryAuthorization,
  type CanaryAuthorizationOutcomeProof,
  type CanaryAuthorizationProof,
} from '@folklore/contracts';
import { decryptPayload, type EncryptedPayload } from '../ingest/receiver.js';
import type { CanaryAuthorizationConsumer } from '../ingest/HttpCanaryAuthorizationConsumer.js';
import { PipelineProcessingError, type ProcessedFact } from '../pipeline/index.js';
import type { OAuthRefreshCommand, OAuthRefreshMetadataUpdate } from '@folklore/contracts/enclave';
import { pullDueMessageSchema } from '@folklore/contracts/enclave';
import { z } from 'zod';
import {
  jiraEncryptedWebhookEnvelopeSchema,
  type WebhookLifecycleDelivery,
} from '@folklore/contracts/enclave';
import {
  buildPullCompleteSignal,
  runPull,
  type PullRunnerDeps,
  type PullCompleteSignal,
  type PullDueMessage,
} from '../pull/pull-runner.js';
import type { TenantContext } from './tenant-context.js';
import type { TenantRegistry } from './tenant-registry.js';
import type {
  JiraWebhookAuthenticationInput,
  JiraWebhookAuthenticator,
} from '../ingest/JiraWebhookAuthenticator.js';
import {
  getDecryptedConnectionForKind,
  type DecryptedSourceConnection,
  type SourceConnectionResolution,
} from '../pull/source-connections-client.js';
import { withInferenceReceiptContext } from '../inference/inference-receipt-context.js';
import { CodebaseSelectionStore } from '../codebase/CodebaseSelectionStore.js';
import { errorType } from '../logging/error-fields.js';

export interface IngestMessage {
  encryption_version: 2;
  tenant_id: string;
  source: string;
  eventType?: string;
  type?: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  canary_run_id?: string;
  request_id?: string;
  canary_authorization?: CanaryAuthorization;
}

export type RoutableMessage = IngestMessage | PullDueMessage;

const ingestMessageSchema = z.object({
  encryption_version: z.literal(2),
  tenant_id: z.string(),
  source: z.string(),
  eventType: z.string().optional(),
  type: z.string().optional(),
  ephemeralPublicKey: z.string(),
  nonce: z.string(),
  ciphertext: z.string(),
});

export function parseRoutableMessage(input: unknown): RoutableMessage {
  const pull = pullDueMessageSchema.safeParse(input);
  if (pull.success) return pull.data;
  const ingest = ingestMessageSchema.safeParse(input);
  if (ingest.success && ingest.data.type !== 'pull-due') return ingest.data;
  throw pull.error;
}

export interface RoutedResult {
  context: TenantContext;
  facts: ProcessedFact[];
  pullComplete?: PullCompleteSignal;
  afterDurablePersistence?: () => Promise<void>;
  requiresDurablePersistence?: boolean;
  shouldAcknowledge: boolean;
  commitReplay?: () => Promise<void>;
  releaseReplay?: () => Promise<void>;
}

export interface TenantMessageRouterDeps {
  registry: TenantRegistry;
  ssm: SSMClient;
  s3?: S3Client;
  processedBucket?: string;
  controlPlaneUrl: string;
  controlPlaneFetch: typeof globalThis.fetch;
  deploymentId: string;
  agentToken: () => string;
  refreshOAuthCredential?: (input: OAuthRefreshCommand) => Promise<OAuthRefreshMetadataUpdate>;
  jiraWebhookLifecycle?: PullRunnerDeps['jiraWebhookLifecycle'];
  jiraWebhookAuthenticator?: Pick<JiraWebhookAuthenticator, 'authenticate'>;
  recordJiraWebhookDelivery?: (
    input: WebhookLifecycleDelivery,
  ) => Promise<'updated' | 'stale' | 'invalid_submission'>;
  mintGitHubInstallationToken?: (input: {
    installationId: string;
  }) => Promise<{ accessToken: string; expiresAt: string }>;
  canaryProofSigner?: CanaryProofSigner;
  canaryProofSink?: (proof: CanaryAuthorizationOutcomeProof) => Promise<void>;
  canaryAuthorizationConsumer?: CanaryAuthorizationConsumer;
}

export interface CanaryProofSigner {
  sign(
    payload: Uint8Array,
  ):
    | { publicKey: Uint8Array; signature: Uint8Array }
    | Promise<{ publicKey: Uint8Array; signature: Uint8Array }>;
  sessionPublicKey(): Uint8Array | Promise<Uint8Array>;
}

// A message arrived on a queue owned by one tenant but its body names a different one — the two
// authorities disagree, so it is poison, never processed. Content-free: only tenant ids.
export class CrossTenantRoutingError extends Error {
  constructor(
    readonly queueTenantId: string,
    readonly messageTenantId: string,
  ) {
    super(`message for ${messageTenantId} arrived on ${queueTenantId}'s queue`);
    this.name = 'CrossTenantRoutingError';
  }
}

export type TenantMessageRoutePhase =
  | 'decrypt'
  | 'pipeline'
  | 'encrypt'
  | 'store'
  | 'embed'
  | 'index';

export class TenantMessageRouteError extends Error {
  constructor(
    readonly phase: TenantMessageRoutePhase,
    readonly errorType: string,
  ) {
    super('tenant_message_route_failed');
    this.name = 'TenantMessageRouteError';
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
      const codebaseSelectionStore =
        raw.kind === 'code' && this.deps.s3
          ? (() => {
              const scope = context.codebaseSelectionScope();
              return new CodebaseSelectionStore({
                s3: this.deps.s3,
                bucket: scope.bucket,
                crypto: scope.crypto,
              });
            })()
          : undefined;
      const result = await runPull(raw, {
        ssm: this.deps.ssm,
        s3: this.deps.s3,
        processedBucket: context.processedOutputsBucket || this.deps.processedBucket,
        orgId: queueTenantId,
        crypto: context.crypto,
        controlPlaneUrl: this.deps.controlPlaneUrl,
        controlPlaneFetch: this.deps.controlPlaneFetch,
        runtimeDeploymentId: this.deps.deploymentId,
        deploymentId:
          context.tenantDeploymentId ?? (context.deploymentId || this.deps.deploymentId),
        agentToken: this.deps.agentToken(),
        pipeline: context.pipeline,
        refreshOAuthCredential: this.deps.refreshOAuthCredential,
        jiraWebhookLifecycle: this.deps.jiraWebhookLifecycle,
        mintGitHubInstallationToken: this.deps.mintGitHubInstallationToken,
        ...(codebaseSelectionStore ? { codebaseSelectionStore } : {}),
      });
      if (result.outcome === 'not_processed') {
        return { context, facts: [], shouldAcknowledge: false };
      }
      if (result.outcome === 'superseded') {
        return {
          context,
          facts: [],
          requiresDurablePersistence: false,
          shouldAcknowledge: true,
        };
      }
      return {
        context,
        facts: result.facts,
        pullComplete: buildPullCompleteSignal(raw),
        afterDurablePersistence: result.persistCursor,
        shouldAcknowledge: true,
      };
    }

    const payload: EncryptedPayload = {
      ephemeralPublicKey: raw.ephemeralPublicKey,
      nonce: raw.nonce,
      ciphertext: raw.ciphertext,
    };
    if (raw.encryption_version !== 2) throw new Error('unsupported_ingest_encryption_version');
    this.validateCanaryAuthorization(raw);
    let plaintext: Buffer;
    try {
      plaintext = decryptPayload(payload, context.ingestPrivateKey, {
        version: raw.encryption_version,
        tenantId: raw.tenant_id,
        source: raw.source,
        type: raw.type,
        eventType: raw.eventType,
        canaryRunId: raw.canary_run_id,
        requestId: raw.request_id,
        canaryAuthorization: raw.canary_authorization,
      });
    } catch (error) {
      throw new TenantMessageRouteError('decrypt', errorType(error));
    }
    this.validateCanaryBody(raw.canary_authorization, plaintext);
    const canaryProof = raw.canary_authorization
      ? await this.createCanaryProof(raw.canary_authorization)
      : undefined;
    if (raw.type === 'jira-oauth-envelope') {
      try {
        const result = await this.routeJiraOAuthEnvelope(raw, context, plaintext);
        return { context, ...result, shouldAcknowledge: true };
      } finally {
        plaintext.fill(0);
      }
    }
    let canaryClaimed = false;
    try {
      if (canaryProof) {
        canaryClaimed = await this.claimCanaryAuthorization(canaryProof);
        if (!canaryClaimed) throw new Error('canary_authorization_invalid');
      }
      const receiptContext =
        raw.canary_run_id && raw.request_id
          ? { canary_run_id: raw.canary_run_id, request_id: raw.request_id }
          : undefined;
      let facts: ProcessedFact[];
      try {
        facts = await withInferenceReceiptContext(receiptContext, () =>
          raw.type === 'pull-normalized'
            ? context.pipeline.handleNormalized(plaintext, raw.source)
            : context.pipeline.handle(plaintext, raw.source, raw.eventType ?? ''),
        );
      } catch (error) {
        if (error instanceof PipelineProcessingError) {
          throw new TenantMessageRouteError(error.phase, error.errorType);
        }
        throw new TenantMessageRouteError('pipeline', errorType(error));
      }
      if (canaryProof && raw.canary_authorization) {
        const outcomeProof = await this.createCanaryOutcomeProof(raw.canary_authorization, facts);
        const completed = await this.completeCanaryAuthorization(outcomeProof);
        if (!completed) throw new Error('canary_authorization_invalid');
        await this.emitCanaryProof(outcomeProof);
      }
      return { context, facts, shouldAcknowledge: true };
    } catch (error) {
      if (canaryProof && canaryClaimed) await this.releaseCanaryAuthorization(canaryProof);
      throw error;
    } finally {
      plaintext.fill(0);
    }
  }

  private validateCanaryAuthorization(raw: IngestMessage): void {
    const authorization = raw.canary_authorization;
    if (!authorization) {
      if (raw.canary_run_id || raw.request_id) throw new Error('canary_authorization_invalid');
      return;
    }
    const issuedAt = Date.parse(authorization.issued_at);
    const expiresAt = Date.parse(authorization.expires_at);
    if (
      raw.source !== 'github' ||
      authorization.org_id !== raw.tenant_id ||
      authorization.deployment_id !== this.deps.deploymentId ||
      authorization.canary_run_id !== raw.canary_run_id ||
      authorization.request_id !== raw.request_id ||
      !Number.isFinite(issuedAt) ||
      !Number.isFinite(expiresAt) ||
      issuedAt > Date.now() ||
      expiresAt <= Date.now() ||
      !this.deps.canaryProofSigner ||
      !this.deps.canaryAuthorizationConsumer
    ) {
      throw new Error('canary_authorization_invalid');
    }
  }

  private async claimCanaryAuthorization(proof: CanaryAuthorizationProof): Promise<boolean> {
    try {
      return (await this.deps.canaryAuthorizationConsumer?.claim(proof)) === true;
    } catch {
      return false;
    }
  }

  private async completeCanaryAuthorization(
    proof: CanaryAuthorizationOutcomeProof,
  ): Promise<boolean> {
    try {
      return (await this.deps.canaryAuthorizationConsumer?.complete(proof)) === true;
    } catch {
      return false;
    }
  }

  private async releaseCanaryAuthorization(proof: CanaryAuthorizationProof): Promise<void> {
    try {
      await this.deps.canaryAuthorizationConsumer?.release(proof);
    } catch {
      // A failed release leaves the short claim lease to expire; it does not consume the capability.
    }
  }

  private async emitCanaryProof(proof: CanaryAuthorizationOutcomeProof): Promise<void> {
    try {
      await this.deps.canaryProofSink?.(proof);
    } catch {
      // Durable completion is the evidence source; Redis is only a retryable delivery hint.
    }
  }

  private validateCanaryBody(
    authorization: CanaryAuthorization | undefined,
    plaintext: Buffer,
  ): void {
    if (!authorization) return;
    const digest = createHash('sha256').update(plaintext).digest('hex');
    if (digest !== authorization.body_sha256) throw new Error('canary_authorization_invalid');
  }

  private async createCanaryProof(
    authorization: CanaryAuthorization,
  ): Promise<CanaryAuthorizationProof> {
    const signer = this.deps.canaryProofSigner;
    if (!signer) throw new Error('canary_authorization_invalid');
    const publicKey = await signer.sessionPublicKey();
    const publicKeyBase64 = Buffer.from(publicKey).toString('base64');
    const keyDigest = createHash('sha256').update(publicKey).digest('hex');
    if (keyDigest !== authorization.attestation_session_key_sha256) {
      throw new Error('canary_authorization_invalid');
    }
    const unsigned = { ...authorization, public_key: publicKeyBase64 };
    const signed = await signer.sign(
      Buffer.from(
        canaryAuthorizationProofPayload({ ...unsigned, public_key: publicKeyBase64 }),
        'utf8',
      ),
    );
    if (!Buffer.from(signed.publicKey).equals(publicKey)) {
      throw new Error('canary_authorization_invalid');
    }
    return {
      ...unsigned,
      public_key: publicKeyBase64,
      signature: Buffer.from(signed.signature).toString('base64'),
    };
  }

  private async createCanaryOutcomeProof(
    authorization: CanaryAuthorization,
    facts: readonly ProcessedFact[],
  ): Promise<CanaryAuthorizationOutcomeProof> {
    const signer = this.deps.canaryProofSigner;
    if (!signer) throw new Error('canary_authorization_invalid');
    const publicKey = await signer.sessionPublicKey();
    const publicKeyBase64 = Buffer.from(publicKey).toString('base64');
    const keyDigest = createHash('sha256').update(publicKey).digest('hex');
    if (keyDigest !== authorization.attestation_session_key_sha256) {
      throw new Error('canary_authorization_invalid');
    }
    const unsigned = {
      ...authorization,
      public_key: publicKeyBase64,
      status: 'succeeded' as const,
      fact_count: facts.length,
      outcome_sha256: createHash('sha256')
        .update(
          canaryPipelineOutcomePayload({
            authorization_id: authorization.authorization_id,
            body_sha256: authorization.body_sha256,
            fact_count: facts.length,
            fact_digests: facts.map((fact) => ({
              fact_id: fact.factId,
              body_sha256: fact.bodyHash,
            })),
          }),
        )
        .digest('hex'),
    };
    const signed = await signer.sign(
      Buffer.from(canaryAuthorizationOutcomeProofPayload(unsigned), 'utf8'),
    );
    if (!Buffer.from(signed.publicKey).equals(publicKey)) {
      throw new Error('canary_authorization_invalid');
    }
    return {
      ...unsigned,
      signature: Buffer.from(signed.signature).toString('base64'),
    };
  }

  private async routeJiraOAuthEnvelope(
    raw: IngestMessage,
    context: TenantContext,
    plaintext: Buffer,
  ): Promise<{
    facts: ProcessedFact[];
    commitReplay?: () => Promise<void>;
    releaseReplay?: () => Promise<void>;
  }> {
    const authenticator = this.deps.jiraWebhookAuthenticator;
    const recordDelivery = this.deps.recordJiraWebhookDelivery;
    if (!authenticator || !recordDelivery) {
      return { facts: [] };
    }
    let envelope: unknown;
    try {
      envelope = JSON.parse(plaintext.toString('utf8')) as unknown;
    } catch {
      return { facts: [] };
    }
    const parsed = jiraEncryptedWebhookEnvelopeSchema.safeParse(envelope);
    if (!parsed.success || raw.source !== 'jira') return { facts: [] };
    const tenantDeploymentId = context.tenantDeploymentId ?? this.deps.deploymentId;
    const resolution = (await getDecryptedConnectionForKind(
      this.deps.controlPlaneUrl,
      this.deps.deploymentId,
      tenantDeploymentId,
      this.deps.agentToken(),
      'jira',
      context.tenantId,
      context.crypto,
      this.deps.controlPlaneFetch,
    )) as SourceConnectionResolution | DecryptedSourceConnection;
    const connection = this.resolveConnection(resolution);
    if (!connection) return { facts: [] };
    if (!connection.externalTenantId || !connection.webhookRouteId) return { facts: [] };
    const webhookRouteId = connection.webhookRouteId;
    const authInput: JiraWebhookAuthenticationInput = {
      orgId: context.tenantId,
      sourceKind: connection.kind,
      externalTenantId: connection.externalTenantId,
      webhookRouteId,
      webhookRegistrationIds: connection.webhookRegistrationIds,
      authorization: parsed.data.authorization,
      method: parsed.data.method,
      rawPath: parsed.data.rawPath,
      rawQuery: parsed.data.rawQuery,
      webhookIdentifier: parsed.data.webhookIdentifier,
    };
    const authenticated = await authenticator.authenticate(authInput);
    if (!authenticated) return { facts: [] };
    try {
      const facts = await context.pipeline.handle(
        Buffer.from(parsed.data.rawBody, 'utf8'),
        raw.source,
        raw.eventType ?? '',
      );
      return {
        facts,
        commitReplay: async () => {
          const receipt = await recordDelivery({
            runtimeDeploymentId: this.deps.deploymentId,
            tenantDeploymentId,
            orgId: context.tenantId,
            connectionId: connection.connectionId,
            webhookRouteId,
            sourceKind: connection.kind,
            attestationGeneration: connection.attestationGeneration,
            registrationId: authenticated.registrationId,
          });
          if (receipt === 'invalid_submission') throw new Error('jira_webhook_delivery_invalid');
          await authenticated.commitReplay();
        },
        releaseReplay: authenticated.releaseReplay,
      };
    } catch (error) {
      await authenticated.releaseReplay();
      throw error;
    }
  }

  private resolveConnection(
    resolution: SourceConnectionResolution | DecryptedSourceConnection,
  ): DecryptedSourceConnection | undefined {
    if (!('outcome' in resolution)) return resolution;
    if (resolution.outcome === 'not_processed') {
      throw new Error('jira_source_connection_unavailable');
    }
    return resolution.outcome === 'connected' ? resolution.connection : undefined;
  }
}
