import {
  memberIdentityLinksResponseSchema,
  type MemberIdentityLinkAckRequest,
  type PendingMemberIdentityLink,
} from '@folklore/contracts';
import { assertControlPlaneOrigin } from '../pull/control-plane-url.js';
import type { MemberIdentityLinkSourcePort } from './MemberIdentityLinkRelay.js';

const REQUEST_TIMEOUT_MS = 10_000;
const AGENT_TOKEN_MISSING = 'member_link_agent_token_missing';
const FETCH_FAILED = 'member_link_fetch_failed';
const RESPONSE_INVALID = 'member_link_response_invalid';

export interface ControlPlaneTenantMemberIdentityLinkSourceDeps {
  readonly controlPlaneUrl: string;
  readonly runtimeDeploymentId: string;
  readonly tenantDeploymentId: string;
  readonly orgId: string;
  readonly agentToken: () => string;
  readonly fetchImpl: typeof globalThis.fetch;
}

/** One assigned tenant's confirmed member links, read and acked through the control plane by this runtime. */
export class ControlPlaneTenantMemberIdentityLinkSource implements MemberIdentityLinkSourcePort {
  constructor(private readonly deps: ControlPlaneTenantMemberIdentityLinkSourceDeps) {
    assertControlPlaneOrigin(deps.controlPlaneUrl);
  }

  async list(): Promise<PendingMemberIdentityLink[]> {
    const response = await this.request(this.linksUrl(), { method: 'GET' });
    const parsed = memberIdentityLinksResponseSchema.safeParse(await this.readBody(response));
    if (!parsed.success) throw new Error(RESPONSE_INVALID);
    return parsed.data.links.filter((link) => link.orgId === this.deps.orgId);
  }

  async ack(ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    const body: MemberIdentityLinkAckRequest = { ids: [...ids] };
    await this.request(this.linksUrl('/ack'), {
      method: 'POST',
      contentType: 'application/json',
      body: JSON.stringify(body),
    });
  }

  // The status, the body and any thrown message stay out of the error: each can quote a member email.
  private async request(
    url: string,
    init: { method: 'GET' | 'POST'; contentType?: string; body?: string },
  ): Promise<Response> {
    const token = this.deps.agentToken();
    if (!token) throw new Error(AGENT_TOKEN_MISSING);
    let response: Response;
    try {
      response = await this.deps.fetchImpl(url, {
        method: init.method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(init.contentType ? { 'content-type': init.contentType } : {}),
        },
        ...(init.body === undefined ? {} : { body: init.body }),
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new Error(FETCH_FAILED);
    }
    if (!response.ok) throw new Error(FETCH_FAILED);
    return response;
  }

  // A JSON SyntaxError quotes the body it choked on, so it is replaced with a fixed code.
  private async readBody(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new Error(RESPONSE_INVALID);
    }
  }

  private linksUrl(suffix = ''): string {
    const query = new URLSearchParams({
      orgId: this.deps.orgId,
      tenantDeploymentId: this.deps.tenantDeploymentId,
    });
    const deployment = encodeURIComponent(this.deps.runtimeDeploymentId);
    return `${this.deps.controlPlaneUrl}/v1/deployments/${deployment}/member-identity-links${suffix}?${query.toString()}`;
  }
}
