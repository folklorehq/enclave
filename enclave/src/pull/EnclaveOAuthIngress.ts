import { timingSafeEqual } from 'node:crypto';
import { Hono, type Context } from 'hono';
import type { ZodType } from 'zod';
import type { Logger } from '@folklore/core';
import {
  connectorOAuthMetadataUpdateSchema,
  oauthDisconnectCleanupCommandSchema,
  sealedAuthorizationCodeSubmissionSchema,
  sealedGitHubInstallationSubmissionSchema,
  type ConnectorOAuthMetadataUpdate,
  type OAuthDisconnectCleanupCommand,
  type SealedAuthorizationCodeSubmission,
  type SealedGitHubInstallationSubmission,
} from '@folklore/contracts/enclave';
import {
  memberIdentityLinkPersistenceSchema,
  type MemberIdentityLinkPersistence,
} from '@folklore/contracts';
import { redemptionRefusalReason } from './oauth-failure-reason.js';

const MAX_SUBMISSION_BYTES = 2_100_000;
const BEARER_PREFIX = 'Bearer ';
const REDEMPTION_FAILED = 'oauth_redemption_failed';

type RedemptionOperation = 'source' | 'member_identity' | 'github_installation';

export interface EnclaveOAuthIngressHandlers {
  resolveGeneration(input: { orgId: string; deploymentId: string }): Promise<string | null>;
  redeemSource(
    input: SealedAuthorizationCodeSubmission,
    generation: string,
  ): Promise<ConnectorOAuthMetadataUpdate>;
  redeemMemberIdentity(
    input: SealedAuthorizationCodeSubmission,
    generation: string,
  ): Promise<MemberIdentityLinkPersistence>;
  redeemGitHubInstallation(
    input: SealedGitHubInstallationSubmission,
    generation: string,
  ): Promise<ConnectorOAuthMetadataUpdate>;
  cleanupDisconnect?(input: OAuthDisconnectCleanupCommand): Promise<void>;
}

export interface EnclaveOAuthIngressOptions {
  /** Deployment token loaded from SSM; callbacks never authenticate with a public URL alone. */
  authorizationToken: string;
  maxBodyBytes?: number;
  logger?: Logger;
}

/** HTTP boundary for opaque OAuth envelopes; all redemption and persistence remain in enclave RAM. */
export class EnclaveOAuthIngress {
  readonly app: Hono;
  private readonly maxBodyBytes: number;
  private readonly logger: Logger | undefined;

  constructor(
    private readonly handlers: EnclaveOAuthIngressHandlers,
    options: EnclaveOAuthIngressOptions,
  ) {
    if (!options.authorizationToken) throw new Error('oauth_ingress_auth_unavailable');
    this.maxBodyBytes = options.maxBodyBytes ?? MAX_SUBMISSION_BYTES;
    if (!Number.isSafeInteger(this.maxBodyBytes) || this.maxBodyBytes < 1) {
      throw new Error('oauth_ingress_body_limit_invalid');
    }
    this.authorizationToken = options.authorizationToken;
    this.logger = options.logger;
    this.app = new Hono();
    this.app.post('/source', (context) => this.handleSource(context));
    this.app.post('/member-identity', (context) => this.handleMemberIdentity(context));
    this.app.post('/github-installation', (context) => this.handleGitHubInstallation(context));
    this.app.post('/disconnect-cleanup', (context) => this.handleDisconnectCleanup(context));
  }

  get fetch(): (request: Request) => Promise<Response> {
    return async (request) => this.app.fetch(request);
  }

  private async handleSource(context: Context) {
    return this.handle(
      context,
      'source',
      sealedAuthorizationCodeSubmissionSchema,
      connectorOAuthMetadataUpdateSchema,
      (input, generation) => this.handlers.redeemSource(input, generation),
    );
  }

  private async handleMemberIdentity(context: Context) {
    return this.handle(
      context,
      'member_identity',
      sealedAuthorizationCodeSubmissionSchema,
      memberIdentityLinkPersistenceSchema,
      (input, generation) => this.handlers.redeemMemberIdentity(input, generation),
    );
  }

  private async handleGitHubInstallation(context: Context) {
    return this.handle(
      context,
      'github_installation',
      sealedGitHubInstallationSubmissionSchema,
      connectorOAuthMetadataUpdateSchema,
      (input, generation) => this.handlers.redeemGitHubInstallation(input, generation),
    );
  }

  private async handleDisconnectCleanup(context: Context): Promise<Response> {
    if (!this.authorized(context.req.header('authorization'))) {
      return context.json({ error: 'unauthorized' }, 401);
    }
    if (!this.handlers.cleanupDisconnect) return context.json({ error: 'unavailable' }, 503);
    const body = await this.readBody(context.req.raw);
    const parsed = oauthDisconnectCleanupCommandSchema.safeParse(body);
    if (!parsed.success) return context.json({ error: 'invalid_submission' }, 400);
    const activeGeneration = await this.handlers.resolveGeneration({
      orgId: parsed.data.orgId,
      deploymentId: parsed.data.tenantDeploymentId,
    });
    if (!activeGeneration) {
      return context.json({ error: 'attestation_unavailable' }, 409);
    }
    // Cleanup keeps the retired generation for credential AAD; the live lease above authorizes the enclave.
    try {
      await this.handlers.cleanupDisconnect(parsed.data);
      return context.json({ completed: true }, 200);
    } catch {
      return context.json({ error: 'cleanup_failed' }, 503);
    }
  }

  private async handle<
    T extends SealedAuthorizationCodeSubmission | SealedGitHubInstallationSubmission,
    R extends ConnectorOAuthMetadataUpdate | MemberIdentityLinkPersistence,
  >(
    context: Context,
    operation: RedemptionOperation,
    schema: ZodType<T>,
    resultSchema: ZodType<R>,
    redeem: (input: T, generation: string) => Promise<R>,
  ): Promise<Response> {
    if (!this.authorized(context.req.header('authorization'))) {
      return context.json({ error: 'unauthorized' }, 401);
    }
    const body = await this.readBody(context.req.raw);
    if (!body) return context.json({ error: 'invalid_submission' }, 400);
    const parsed = schema.safeParse(body);
    if (!parsed.success) return context.json({ error: 'invalid_submission' }, 400);
    const generation = await this.handlers.resolveGeneration({
      orgId: parsed.data.orgId,
      deploymentId: parsed.data.deploymentId,
    });
    if (!generation || generation !== parsed.data.attestationGeneration) {
      return context.json({ error: 'attestation_unavailable' }, 409);
    }
    try {
      const metadata = await redeem(parsed.data, generation);
      resultSchema.parse(metadata);
      return context.json({ accepted: true }, 202);
    } catch (error) {
      return this.refuseRedemption(context, operation, error);
    }
  }

  private refuseRedemption(
    context: Context,
    operation: RedemptionOperation,
    error: unknown,
  ): Response {
    const reason = redemptionRefusalReason(error);
    this.logger?.warn('oauth_ingress.redemption_refused', { errorCode: reason, operation });
    return context.json({ error: REDEMPTION_FAILED, reason }, 503);
  }

  private async readBody(request: Request): Promise<unknown | null> {
    const declared = request.headers.get('content-length');
    if (declared !== null) {
      const length = Number(declared);
      if (!Number.isSafeInteger(length) || length < 0 || length > this.maxBodyBytes) return null;
    }
    try {
      const bytes = new Uint8Array(await request.arrayBuffer());
      if (bytes.byteLength > this.maxBodyBytes) return null;
      return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    } catch {
      return null;
    }
  }

  private authorized(value: string | undefined): boolean {
    const expected = Buffer.from(this.authorizationToken, 'utf8');
    const supplied = Buffer.from(
      value?.startsWith(BEARER_PREFIX) ? value.slice(BEARER_PREFIX.length) : '',
      'utf8',
    );
    return (
      expected.byteLength > 0 &&
      expected.byteLength === supplied.byteLength &&
      timingSafeEqual(expected, supplied)
    );
  }

  private readonly authorizationToken: string;
}
