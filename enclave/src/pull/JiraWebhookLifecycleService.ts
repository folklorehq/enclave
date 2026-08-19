import { ProviderRejectedError } from '../egress/provider-token-fetch.js';
import type { WebhookLifecycleClaim, WebhookLifecycleFinalize } from '@folklore/contracts/enclave';
import type { WebhookLifecyclePersistence } from './HttpOAuthCredentialPersistence.js';
import type { JiraWebhookClientPort, JiraWebhookRegistration } from './HttpJiraWebhookClient.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GENERATION_PATTERN = /^[A-Za-z0-9._:-]+$/;
const RENEWAL_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000;
const FAILURE_BACKOFF_MS = 60 * 60 * 1000;
const MAX_ID_DIGITS = 16;
const EXPECTED_EVENTS = [
  'jira:issue_created',
  'jira:issue_updated',
  'comment_created',
  'comment_updated',
] as const;

export type JiraWebhookMode = 'off' | 'capture' | 'enabled';

export interface JiraWebhookLifecycleInput {
  runtimeDeploymentId: string;
  tenantDeploymentId: string;
  orgId: string;
  connectionId: string;
  sourceKind: string;
  attestationGeneration: string;
  externalTenantId: string;
  accessToken: string;
  webhookRouteId: string;
  webhookRevision: number;
  webhookRegistrationIds: readonly string[] | null;
  webhookExpiresAt: string | null;
  webhookStatus: 'registered' | 'degraded' | null;
  webhookLastAttemptedAt: string | null;
  webhookCleanupRouteId?: string | null;
  webhookCleanupExternalTenantId?: string | null;
  webhookCleanupRegistrationIds?: readonly string[] | null;
}

export interface JiraWebhookLifecycleServiceOptions {
  clock?: () => Date;
  mode?: JiraWebhookMode;
  isEnabledForOrg?: (orgId: string) => boolean;
}

interface Claim {
  claimId: string;
  revision: number;
}

interface SuccessfulReconciliation {
  operation: 'register' | 'refresh' | 'adopt';
  registrationIds: string[];
  expiresAt: string;
}

/** Reconciles one signed Jira webhook route without changing pull success semantics. */
export class JiraWebhookLifecycleService {
  private readonly clock: () => Date;
  private readonly mode: JiraWebhookMode;
  private readonly isEnabledForOrg: (orgId: string) => boolean;

  constructor(
    private readonly jira: JiraWebhookClientPort,
    private readonly persistence: WebhookLifecyclePersistence,
    options: JiraWebhookLifecycleServiceOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.mode = options.mode ?? 'off';
    this.isEnabledForOrg = options.isEnabledForOrg ?? (() => false);
  }

  async reconcile(
    input: JiraWebhookLifecycleInput,
  ): Promise<'skipped' | 'registered' | 'degraded'> {
    const now = this.clock();
    if (!this.canReconcile(input, now) || !this.isEnabled(input)) return 'skipped';
    if (this.isHealthy(input, now)) return 'skipped';
    if (this.isInFailureBackoff(input, now)) return 'degraded';

    const claim = await this.claim(input, input.webhookRevision);
    if (!claim) return 'skipped';
    const attemptedAt = now.toISOString();
    let replacementCleaned = false;
    let claimLost = false;
    try {
      replacementCleaned = await this.cleanupReplacement(input, claim);
    } catch {
      claimLost = true;
    }

    let success: SuccessfulReconciliation | null = null;
    let failureCode: 'provider_rejected' | 'provider_error' = 'provider_error';
    if (!claimLost) {
      try {
        success = await this.reconcileProvider(input, now, claim);
      } catch (error) {
        failureCode =
          error instanceof ProviderRejectedError ? 'provider_rejected' : 'provider_error';
      }
    }

    if (replacementCleaned) await this.clearReplacement(input, claim);
    const finalized = await this.finalize(input, claim, attemptedAt, success, failureCode, now);
    if (finalized !== 'updated') {
      await this.cleanupUncommittedRegistration(input, success, claim);
      return 'degraded';
    }
    return success ? 'registered' : 'degraded';
  }

  private async claim(
    input: JiraWebhookLifecycleInput,
    expectedRevision: number,
  ): Promise<Claim | null> {
    const claimInput: WebhookLifecycleClaim = {
      runtimeDeploymentId: input.runtimeDeploymentId,
      tenantDeploymentId: input.tenantDeploymentId,
      orgId: input.orgId,
      connectionId: input.connectionId,
      webhookRouteId: input.webhookRouteId,
      sourceKind: input.sourceKind,
      attestationGeneration: input.attestationGeneration,
      expectedRevision,
    };
    try {
      const result = await this.persistence.claimWebhookLifecycle(claimInput);
      return typeof result === 'object' ? result : null;
    } catch {
      return null;
    }
  }

  private async reconcileProvider(
    input: JiraWebhookLifecycleInput,
    now: Date,
    claim: Claim,
  ): Promise<SuccessfulReconciliation> {
    const localIds = this.validIds(input.webhookRegistrationIds);
    if (localIds) {
      let refreshed: Awaited<ReturnType<JiraWebhookClientPort['refresh']>> | undefined;
      let listedAfterRefresh: readonly JiraWebhookRegistration[] | undefined;
      try {
        refreshed = await this.jira.refresh({
          cloudId: input.externalTenantId,
          accessToken: input.accessToken,
          registrationIds: localIds,
        });
        listedAfterRefresh = await this.jira.list({
          cloudId: input.externalTenantId,
          accessToken: input.accessToken,
        });
      } catch {
        // A later list can adopt an existing exact registration after a partial refresh failure.
      }
      if (
        refreshed &&
        listedAfterRefresh &&
        this.isFuture(refreshed.expiresAt, now) &&
        this.hasEveryRegistration(listedAfterRefresh, localIds, input, now)
      ) {
        await this.renewClaim(input, claim);
        await this.deleteRouteDuplicates(listedAfterRefresh, localIds, input);
        return {
          operation: 'refresh',
          registrationIds: localIds,
          expiresAt: refreshed.expiresAt,
        };
      }
    }

    const listed = await this.jira.list({
      cloudId: input.externalTenantId,
      accessToken: input.accessToken,
    });
    return this.reconcileListed(input, listed, now, claim);
  }

  private async reconcileListed(
    input: JiraWebhookLifecycleInput,
    listed: readonly JiraWebhookRegistration[],
    now: Date,
    claim: Claim,
  ): Promise<SuccessfulReconciliation> {
    const url = this.webhookUrl(input);
    const exactUrl = listed.filter((registration) => registration.url === url);
    const valid = exactUrl.filter((registration) => this.matchesDefinition(registration, now));
    const adopted = valid[0];
    if (adopted) {
      await this.renewClaim(input, claim);
      await this.deleteRouteDuplicates(exactUrl, [adopted.id], input);
      return { operation: 'adopt', registrationIds: [adopted.id], expiresAt: adopted.expiresAt };
    }

    if (exactUrl.length > 0) {
      await this.renewClaim(input, claim);
      await this.jira.delete({
        cloudId: input.externalTenantId,
        accessToken: input.accessToken,
        registrationIds: this.uniqueIds(exactUrl.map((registration) => registration.id)),
      });
    }
    await this.renewClaim(input, claim);
    const registered = await this.jira.register({
      cloudId: input.externalTenantId,
      accessToken: input.accessToken,
      webhookUrl: url,
    });
    if (!this.validIds(registered.registrationIds) || !this.isFuture(registered.expiresAt, now)) {
      throw new Error('jira_webhook_registration_invalid');
    }
    return {
      operation: 'register',
      registrationIds: [...registered.registrationIds],
      expiresAt: registered.expiresAt,
    };
  }

  private async deleteRouteDuplicates(
    registrations: readonly JiraWebhookRegistration[],
    retainedIds: readonly string[],
    input: JiraWebhookLifecycleInput,
  ): Promise<void> {
    const retained = new Set(retainedIds);
    const duplicates = this.uniqueIds(
      registrations
        .filter((registration) => registration.url === this.webhookUrl(input))
        .map((registration) => registration.id)
        .filter((id) => !retained.has(id)),
    );
    if (duplicates.length === 0) return;
    try {
      await this.jira.delete({
        cloudId: input.externalTenantId,
        accessToken: input.accessToken,
        registrationIds: duplicates,
      });
    } catch {
      throw new Error('jira_webhook_duplicate_cleanup_failed');
    }
  }

  private hasEveryRegistration(
    listed: readonly JiraWebhookRegistration[],
    ids: readonly string[],
    input: JiraWebhookLifecycleInput,
    now: Date,
  ): boolean {
    return (
      ids.every((id) => {
        const registration = listed.find((candidate) => candidate.id === id);
        return (
          registration !== undefined &&
          registration.url === this.webhookUrl(input) &&
          this.matchesDefinition(registration, now)
        );
      }) && listed.some((registration) => registration.url === this.webhookUrl(input))
    );
  }

  private matchesDefinition(registration: JiraWebhookRegistration, now: Date): boolean {
    const events = new Set(registration.events);
    return (
      registration.events.length === EXPECTED_EVENTS.length &&
      events.size === EXPECTED_EVENTS.length &&
      EXPECTED_EVENTS.every((event) => events.has(event)) &&
      registration.jqlFilter === '' &&
      this.isFuture(registration.expiresAt, now)
    );
  }

  private async finalize(
    input: JiraWebhookLifecycleInput,
    claim: Claim,
    attemptedAt: string,
    success: SuccessfulReconciliation | null,
    failureCode: 'provider_rejected' | 'provider_error',
    now: Date,
  ): Promise<'updated' | 'stale' | 'invalid_submission'> {
    const active = success ?? this.activeLocalRegistration(input, now);
    const finalization: WebhookLifecycleFinalize = {
      runtimeDeploymentId: input.runtimeDeploymentId,
      tenantDeploymentId: input.tenantDeploymentId,
      orgId: input.orgId,
      connectionId: input.connectionId,
      webhookRouteId: input.webhookRouteId,
      sourceKind: input.sourceKind,
      attestationGeneration: input.attestationGeneration,
      claimId: claim.claimId,
      revision: claim.revision,
      registrationIds: active?.registrationIds ?? null,
      expiresAt: active?.expiresAt ?? null,
      attemptedAt,
      succeededAt: success ? attemptedAt : null,
      status: success ? 'registered' : 'degraded',
      operation: success?.operation ?? 'register',
      failureCode: success ? null : failureCode,
    };
    try {
      return await this.persistence.finalizeWebhookLifecycle(finalization);
    } catch {
      return 'invalid_submission';
    }
  }

  private activeLocalRegistration(
    input: JiraWebhookLifecycleInput,
    now: Date,
  ): { registrationIds: string[]; expiresAt: string } | null {
    const ids = this.validIds(input.webhookRegistrationIds);
    if (!ids || !input.webhookExpiresAt || !this.isFuture(input.webhookExpiresAt, now)) return null;
    return { registrationIds: ids, expiresAt: input.webhookExpiresAt };
  }

  private async cleanupReplacement(
    input: JiraWebhookLifecycleInput,
    claim: Claim,
  ): Promise<boolean> {
    const ids = this.validIds(input.webhookCleanupRegistrationIds);
    const cloudId = input.webhookCleanupExternalTenantId;
    if (!input.webhookCleanupRegistrationIds?.length) return true;
    if (!ids || !cloudId || input.webhookCleanupRouteId === input.webhookRouteId) return false;
    await this.renewClaim(input, claim);
    try {
      await this.jira.delete({ cloudId, accessToken: input.accessToken, registrationIds: ids });
      return true;
    } catch (error) {
      if (error instanceof ProviderRejectedError && error.status === 404) return true;
      // Replaced registrations expire remotely if bounded cleanup cannot complete.
      return false;
    }
  }

  private async renewClaim(input: JiraWebhookLifecycleInput, claim: Claim): Promise<void> {
    const result = await this.persistence.renewWebhookLifecycleClaim({
      runtimeDeploymentId: input.runtimeDeploymentId,
      tenantDeploymentId: input.tenantDeploymentId,
      orgId: input.orgId,
      connectionId: input.connectionId,
      webhookRouteId: input.webhookRouteId,
      sourceKind: input.sourceKind,
      attestationGeneration: input.attestationGeneration,
      claimId: claim.claimId,
      revision: claim.revision,
    });
    if (result !== 'renewed') throw new Error('jira_webhook_claim_lost');
  }

  private async clearReplacement(input: JiraWebhookLifecycleInput, claim: Claim): Promise<void> {
    try {
      await this.persistence.clearWebhookCleanupTombstone({
        runtimeDeploymentId: input.runtimeDeploymentId,
        tenantDeploymentId: input.tenantDeploymentId,
        orgId: input.orgId,
        connectionId: input.connectionId,
        webhookRouteId: input.webhookRouteId,
        sourceKind: input.sourceKind,
        attestationGeneration: input.attestationGeneration,
        claimId: claim.claimId,
        revision: claim.revision,
      });
    } catch {
      // The compare-and-set claim fences a later cleanup attempt.
    }
  }

  private async cleanupUncommittedRegistration(
    input: JiraWebhookLifecycleInput,
    success: SuccessfulReconciliation | null,
    previousClaim: Claim,
  ): Promise<void> {
    if (!success || success.operation !== 'register') return;
    const cleanupClaim = await this.claim(input, previousClaim.revision);
    if (!cleanupClaim) return;
    try {
      await this.renewClaim(input, cleanupClaim);
    } catch {
      return;
    }
    try {
      await this.jira.delete({
        cloudId: input.externalTenantId,
        accessToken: input.accessToken,
        registrationIds: success.registrationIds,
      });
    } catch {
      // The next lifecycle pass can retry only when the provider still exposes the exact route.
      return;
    }
    try {
      await this.persistence.finalizeWebhookLifecycle({
        runtimeDeploymentId: input.runtimeDeploymentId,
        tenantDeploymentId: input.tenantDeploymentId,
        orgId: input.orgId,
        connectionId: input.connectionId,
        webhookRouteId: input.webhookRouteId,
        sourceKind: input.sourceKind,
        attestationGeneration: input.attestationGeneration,
        claimId: cleanupClaim.claimId,
        revision: cleanupClaim.revision,
        registrationIds: null,
        expiresAt: null,
        attemptedAt: this.clock().toISOString(),
        succeededAt: null,
        status: 'degraded',
        operation: 'register',
        failureCode: 'provider_error',
      });
    } catch {
      // A later pass can clear an expired cleanup claim without deleting another worker's route.
    }
  }

  private canReconcile(input: JiraWebhookLifecycleInput, now: Date): boolean {
    return (
      Number.isFinite(now.getTime()) &&
      input.sourceKind === 'jira' &&
      this.isUuid(input.runtimeDeploymentId) &&
      this.isUuid(input.tenantDeploymentId) &&
      this.isUuid(input.orgId) &&
      this.isUuid(input.connectionId) &&
      this.isUuid(input.externalTenantId) &&
      this.isUuid(input.webhookRouteId) &&
      GENERATION_PATTERN.test(input.attestationGeneration) &&
      Number.isSafeInteger(input.webhookRevision) &&
      input.webhookRevision >= 0 &&
      typeof input.accessToken === 'string' &&
      input.accessToken.length > 0
    );
  }

  private isEnabled(input: JiraWebhookLifecycleInput): boolean {
    return this.mode === 'enabled' && this.isEnabledForOrg(input.orgId);
  }

  private isHealthy(input: JiraWebhookLifecycleInput, now: Date): boolean {
    if (input.webhookStatus !== 'registered' || !input.webhookExpiresAt) return false;
    const expiresAt = Date.parse(input.webhookExpiresAt);
    return (
      Number.isFinite(expiresAt) &&
      expiresAt - now.getTime() > RENEWAL_THRESHOLD_MS &&
      this.validIds(input.webhookRegistrationIds) !== null &&
      !this.hasCleanupTombstone(input)
    );
  }

  private hasCleanupTombstone(input: JiraWebhookLifecycleInput): boolean {
    return (
      (input.webhookCleanupRouteId !== undefined && input.webhookCleanupRouteId !== null) ||
      (input.webhookCleanupExternalTenantId !== undefined &&
        input.webhookCleanupExternalTenantId !== null) ||
      (input.webhookCleanupRegistrationIds?.length ?? 0) > 0
    );
  }

  private isInFailureBackoff(input: JiraWebhookLifecycleInput, now: Date): boolean {
    if (input.webhookStatus !== 'degraded' || !input.webhookLastAttemptedAt) return false;
    const attemptedAt = Date.parse(input.webhookLastAttemptedAt);
    return Number.isFinite(attemptedAt) && now.getTime() - attemptedAt < FAILURE_BACKOFF_MS;
  }

  private isFuture(value: string, now: Date): boolean {
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) && timestamp > now.getTime();
  }

  private validIds(values: readonly string[] | null | undefined): string[] | null {
    if (!values || values.length === 0 || values.length > 16) return null;
    if (
      values.some(
        (value) =>
          value.length > MAX_ID_DIGITS ||
          !/^(?:0|[1-9][0-9]*)$/.test(value) ||
          BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER),
      )
    ) {
      return null;
    }
    const ids = [...values];
    return new Set(ids).size === ids.length ? ids : null;
  }

  private uniqueIds(values: readonly string[]): string[] {
    return [...new Set(values)];
  }

  private webhookUrl(input: JiraWebhookLifecycleInput): string {
    return `https://webhooks.folklorehq.com/ingest/${input.orgId}/jira?route=${input.webhookRouteId}`;
  }

  private isUuid(value: string): boolean {
    return UUID_PATTERN.test(value);
  }
}
