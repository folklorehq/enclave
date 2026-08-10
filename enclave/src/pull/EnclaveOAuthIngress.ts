import { timingSafeEqual } from 'node:crypto';
import { Hono, type Context } from 'hono';
import type { ZodType } from 'zod';
import {
  connectorOAuthMetadataUpdateSchema,
  sealedAuthorizationCodeSubmissionSchema,
  sealedGitHubInstallationSubmissionSchema,
  type ConnectorOAuthMetadataUpdate,
  type SealedAuthorizationCodeSubmission,
  type SealedGitHubInstallationSubmission,
} from '@folklore/contracts/enclave';
import {
  memberIdentityLinkPersistenceSchema,
  type MemberIdentityLinkPersistence,
} from '@folklore/contracts';

const MAX_SUBMISSION_BYTES = 2_100_000;
const BEARER_PREFIX = 'Bearer ';

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
}

export interface EnclaveOAuthIngressOptions {
  /** Deployment token loaded from SSM; callbacks never authenticate with a public URL alone. */
  authorizationToken: string;
  maxBodyBytes?: number;
}

/** HTTP boundary for opaque OAuth envelopes; all redemption and persistence remain in enclave RAM. */
export class EnclaveOAuthIngress {
  readonly app: Hono;
  private readonly maxBodyBytes: number;

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
    this.app = new Hono();
    this.app.post('/source', (context) => this.handleSource(context));
    this.app.post('/member-identity', (context) => this.handleMemberIdentity(context));
    this.app.post('/github-installation', (context) => this.handleGitHubInstallation(context));
  }

  get fetch(): (request: Request) => Promise<Response> {
    return async (request) => this.app.fetch(request);
  }

  private async handleSource(context: Context) {
    return this.handle(
      context,
      sealedAuthorizationCodeSubmissionSchema,
      connectorOAuthMetadataUpdateSchema,
      (input, generation) => this.handlers.redeemSource(input, generation),
    );
  }

  private async handleMemberIdentity(context: Context) {
    return this.handle(
      context,
      sealedAuthorizationCodeSubmissionSchema,
      memberIdentityLinkPersistenceSchema,
      (input, generation) => this.handlers.redeemMemberIdentity(input, generation),
    );
  }

  private async handleGitHubInstallation(context: Context) {
    return this.handle(
      context,
      sealedGitHubInstallationSubmissionSchema,
      connectorOAuthMetadataUpdateSchema,
      (input, generation) => this.handlers.redeemGitHubInstallation(input, generation),
    );
  }

  private async handle<
    T extends SealedAuthorizationCodeSubmission | SealedGitHubInstallationSubmission,
    R extends ConnectorOAuthMetadataUpdate | MemberIdentityLinkPersistence,
  >(
    context: Context,
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
    } catch {
      return context.json({ error: 'oauth_redemption_failed' }, 503);
    }
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
