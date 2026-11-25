import type { S3Client } from '@aws-sdk/client-s3';
import { decryptPayload, type EncryptedPayload } from '../ingest/receiver.js';
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
  type PullNotProcessedReason,
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
import { boundGitHubInstallationId } from '../pull/github-installation-binding.js';
import { ResourceScopeUnavailableError } from '../resource-scope/resource-scope-errors.js';
import { TenantResourceScope } from '../resource-scope/TenantResourceScope.js';
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

interface RouteOptions {
  signal?: AbortSignal;
}

export interface RoutedResult {
  context: TenantContext;
  facts: ProcessedFact[];
  pullComplete?: PullCompleteSignal;
  // A paused tick is a settled pull for failure accounting, though it moved no cursor.
  pullPaused?: boolean;
  // The next chunk of a pull the budget cut short; it resumes at the cursor this one persists.
  continuation?: PullDueMessage;
  afterDurablePersistence?: () => Promise<void>;
  requiresDurablePersistence?: boolean;
  shouldAcknowledge: boolean;
  commitReplay?: () => Promise<void>;
  releaseReplay?: () => Promise<void>;
  droppedCode?: typeof GITHUB_BINDING_MISMATCH;
  // The pull runner's fixed not-processed reason, carried into the pull-failed signal.
  failureCode?: PullNotProcessedReason;
}

const UNAVAILABLE_RESOURCE_SCOPE: NonNullable<PullRunnerDeps['resourceScope']> = {
  read: () => Promise.reject(new ResourceScopeUnavailableError()),
  transitionBackfill: () => Promise.reject(new ResourceScopeUnavailableError()),
};

const JIRA_OAUTH_ENVELOPE_TYPE = 'jira-oauth-envelope';
const MESSAGE_TYPE_UNSUPPORTED = 'message_type_unsupported';
const GITHUB_SOURCE = 'github';
const GITHUB_BINDING_MISMATCH = 'github_installation_binding_mismatch';

interface TenantMessageRouterDeps {
  registry: TenantRegistry;
  historyWindow: PullRunnerDeps['historyWindow'];
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

type TenantMessageRoutePhase = 'decrypt' | 'pipeline' | 'encrypt' | 'store' | 'embed' | 'index';

export class TenantMessageRouteError extends Error {
  constructor(
    readonly phase: TenantMessageRoutePhase,
    readonly errorType: string,
    cause?: unknown,
  ) {
    super('tenant_message_route_failed', { cause });
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

  async route(
    raw: RoutableMessage,
    queueTenantId: string,
    options: RouteOptions = {},
  ): Promise<RoutedResult> {
    if (raw.tenant_id !== queueTenantId) {
      throw new CrossTenantRoutingError(queueTenantId, raw.tenant_id);
    }
    const context = this.deps.registry.get(queueTenantId);

    if (isPullDueMessage(raw)) {
      const result = await runPull(raw, {
        historyWindow: this.deps.historyWindow,
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
        ...this.resourceScopeDeps(context, queueTenantId),
        ...(options.signal ? { signal: options.signal } : {}),
      });
      if (result.outcome === 'not_processed') {
        return { context, facts: [], shouldAcknowledge: false, failureCode: result.reason };
      }
      if (result.outcome === 'superseded') return this.acknowledgedWithoutFacts(context);
      if (result.outcome === 'paused') {
        return { ...this.acknowledgedWithoutFacts(context), pullPaused: true };
      }
      return {
        context,
        facts: result.facts,
        // Per chunk, lease token included: an open 15-min lease would expire mid-chain and the
        // planner's re-issued backfill would reset the cursor to the window start.
        pullComplete: buildPullCompleteSignal(raw, new Date(), result.stats),
        ...(result.hasMore ? { continuation: this.continuationOf(raw) } : {}),
        afterDurablePersistence: result.persistCursor,
        shouldAcknowledge: true,
      };
    }

    // The ingest proxy sends no type or the Jira OAuth envelope; anything else is refused before decrypt.
    if (raw.type !== undefined && raw.type !== JIRA_OAUTH_ENVELOPE_TYPE) {
      throw new TenantMessageRouteError('pipeline', MESSAGE_TYPE_UNSUPPORTED);
    }
    const payload: EncryptedPayload = {
      ephemeralPublicKey: raw.ephemeralPublicKey,
      nonce: raw.nonce,
      ciphertext: raw.ciphertext,
    };
    if (raw.encryption_version !== 2) throw new Error('unsupported_ingest_encryption_version');
    let plaintext: Buffer;
    try {
      plaintext = decryptPayload(payload, context.ingestPrivateKey, {
        version: raw.encryption_version,
        tenantId: raw.tenant_id,
        source: raw.source,
        type: raw.type,
        eventType: raw.eventType,
      });
    } catch (error) {
      throw new TenantMessageRouteError('decrypt', errorType(error), error);
    }
    // Every delivery must name the bound install.
    if (raw.source === GITHUB_SOURCE) {
      if (!(await this.isBoundGitHubDelivery(context, plaintext))) {
        plaintext.fill(0);
        return {
          context,
          facts: [],
          requiresDurablePersistence: false,
          shouldAcknowledge: true,
          droppedCode: GITHUB_BINDING_MISMATCH,
        };
      }
    }
    if (raw.type === JIRA_OAUTH_ENVELOPE_TYPE) {
      try {
        const result = await this.routeJiraOAuthEnvelope(raw, context, plaintext);
        return { context, ...result, shouldAcknowledge: true };
      } finally {
        plaintext.fill(0);
      }
    }
    try {
      let facts: ProcessedFact[];
      try {
        facts = await context.pipeline.handle(plaintext, raw.source, raw.eventType ?? '');
      } catch (error) {
        if (error instanceof PipelineProcessingError) {
          throw new TenantMessageRouteError(error.phase, error.errorType, error);
        }
        throw new TenantMessageRouteError('pipeline', errorType(error), error);
      }
      return { context, facts, shouldAcknowledge: true };
    } finally {
      plaintext.fill(0);
    }
  }

  // A context that cannot name its scope location, or a router with no object store, must stop the pull, never read as "not configured".
  private resourceScopeDeps(
    context: TenantContext,
    orgId: string,
  ): Pick<PullRunnerDeps, 'resourceScope'> {
    if (!this.deps.s3) return { resourceScope: UNAVAILABLE_RESOURCE_SCOPE };
    try {
      const scope = context.processedOutputsScope();
      return { resourceScope: new TenantResourceScope({ s3: this.deps.s3, orgId, scope }) };
    } catch {
      return { resourceScope: UNAVAILABLE_RESOURCE_SCOPE };
    }
  }

  private acknowledgedWithoutFacts(context: TenantContext): RoutedResult {
    return { context, facts: [], requiresDurablePersistence: false, shouldAcknowledge: true };
  }

  // A backfill flag would restart from the window start; a member pull keeps its owner or routing refuses the chunk.
  private continuationOf(raw: PullDueMessage): PullDueMessage {
    return {
      type: 'pull-due',
      trigger: 'scheduled',
      tenant_id: raw.tenant_id,
      sourceId: raw.sourceId,
      kind: raw.kind,
      ...(raw.ownerAccountId === undefined ? {} : { ownerAccountId: raw.ownerAccountId }),
      backfill: false,
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

  // Routing follows a control-plane binding; only the installation sealed at connect is trusted.
  private async isBoundGitHubDelivery(context: TenantContext, plaintext: Buffer): Promise<boolean> {
    const installationId = this.deliveryInstallationId(plaintext);
    if (!installationId) return false;
    let resolution: SourceConnectionResolution;
    try {
      resolution = await getDecryptedConnectionForKind(
        this.deps.controlPlaneUrl,
        this.deps.deploymentId,
        context.tenantDeploymentId ?? this.deps.deploymentId,
        this.deps.agentToken(),
        GITHUB_SOURCE,
        context.tenantId,
        context.crypto,
        this.deps.controlPlaneFetch,
      );
    } catch (error) {
      plaintext.fill(0);
      throw new TenantMessageRouteError('pipeline', errorType(error), error);
    }
    if (resolution.outcome === 'not_processed') {
      plaintext.fill(0);
      throw new TenantMessageRouteError('pipeline', resolution.reason);
    }
    if (resolution.outcome !== 'connected') return false;
    try {
      boundGitHubInstallationId(resolution.connection.accessToken, installationId);
      return true;
    } catch {
      return false;
    }
  }

  private deliveryInstallationId(plaintext: Buffer): string | null {
    try {
      const body: unknown = JSON.parse(plaintext.toString('utf8'));
      const installation =
        typeof body === 'object' && body !== null
          ? (body as { installation?: unknown }).installation
          : undefined;
      const id =
        typeof installation === 'object' && installation !== null
          ? (installation as { id?: unknown }).id
          : undefined;
      return typeof id === 'number' && Number.isSafeInteger(id) ? String(id) : null;
    } catch {
      return null;
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
