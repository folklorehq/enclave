import {
  canaryAuthorizationOutcomeProofSchema,
  canaryAuthorizationProofSchema,
  type CanaryAuthorizationOutcomeProof,
  type CanaryAuthorizationProof,
} from '@folklore/contracts';
import { assertControlPlaneOrigin } from '../pull/control-plane-url.js';

const REQUEST_TIMEOUT_MS = 10_000;

export interface CanaryAuthorizationConsumer {
  claim(proof: CanaryAuthorizationProof): Promise<boolean>;
  complete(proof: CanaryAuthorizationOutcomeProof): Promise<boolean>;
  release(proof: CanaryAuthorizationProof): Promise<boolean>;
}

export class HttpCanaryAuthorizationConsumer implements CanaryAuthorizationConsumer {
  constructor(
    private readonly controlPlaneUrl: string,
    private readonly deploymentId: string,
    private readonly agentToken: () => string,
    private readonly fetchImpl: typeof globalThis.fetch,
  ) {
    assertControlPlaneOrigin(controlPlaneUrl);
  }

  claim(proof: CanaryAuthorizationProof): Promise<boolean> {
    return this.request('claim', canaryAuthorizationProofSchema, proof, 'claimed');
  }

  complete(proof: CanaryAuthorizationOutcomeProof): Promise<boolean> {
    return this.request('complete', canaryAuthorizationOutcomeProofSchema, proof, 'completed');
  }

  release(proof: CanaryAuthorizationProof): Promise<boolean> {
    return this.request('release', canaryAuthorizationProofSchema, proof, 'released');
  }

  private async request<T extends object>(
    action: 'claim' | 'complete' | 'release',
    schema: { safeParse(value: unknown): { success: boolean; data?: T } },
    proof: unknown,
    responseKey: 'claimed' | 'completed' | 'released',
  ): Promise<boolean> {
    const parsed = schema.safeParse(proof);
    const token = this.agentToken();
    if (!parsed.success || !parsed.data || !token) return false;
    try {
      const response = await this.fetchImpl(
        `${this.controlPlaneUrl.replace(/\/$/, '')}/v1/deployments/${encodeURIComponent(this.deploymentId)}/canary-authorizations/${action}`,
        {
          method: 'POST',
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify(parsed.data),
          redirect: 'error',
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        },
      );
      if (!response.ok) return false;
      const body: unknown = await response.json();
      return (
        typeof body === 'object' &&
        body !== null &&
        (body as Record<string, unknown>)[responseKey] === true
      );
    } catch {
      return false;
    }
  }
}
