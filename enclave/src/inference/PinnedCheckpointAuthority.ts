import type { AciTrustContext, DurableGenerationHighWaterClientPort } from '@folklore/inference';
import {
  assertDurableCheckpointAgainstContext,
  assertVerifiedActivePolicySnapshotV1,
  type VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';
import type { GenerationContextV1 } from '@folklore/contracts';
import { digest64Schema, identifierSchema } from '@folklore/contracts';
import { GENERATION_CONTEXT_FIELDS } from './renewal-grace.js';

interface PinnedCheckpointAuthorityOptions {
  readonly snapshot: VerifiedActivePolicySnapshotV1;
  readonly expectedContext: GenerationContextV1;
  readonly durable: DurableGenerationHighWaterClientPort;
  readonly trustedTimeContext: AciTrustContext;
}

/** Re-reads the durable high-water before each provider call and refuses it unless the installed checkpoint still serves. */
export class PinnedCheckpointAuthority {
  private readonly snapshot: VerifiedActivePolicySnapshotV1;
  private readonly expectedContext: GenerationContextV1;
  private readonly trustedTimeContext: AciTrustContext;
  private readonly durable: DurableGenerationHighWaterClientPort;

  constructor(options: PinnedCheckpointAuthorityOptions) {
    assertVerifiedActivePolicySnapshotV1(options.snapshot);
    this.snapshot = options.snapshot;
    this.expectedContext = Object.freeze({ ...options.expectedContext });
    this.trustedTimeContext = Object.freeze({ ...options.trustedTimeContext });
    this.durable = options.durable;
    this.assertConstructorBindings();
  }

  async assertPinned(context: AciTrustContext): Promise<void> {
    this.assertTrustedTimeContext(context);
    await this.readPinnedCheckpoint();
  }

  private assertConstructorBindings(): void {
    if (this.snapshot.tenantId !== this.expectedContext.orgId) throw new Error('tenant_mismatch');
    if (
      this.trustedTimeContext.orgId !== this.expectedContext.orgId ||
      this.trustedTimeContext.deploymentId !== this.expectedContext.deploymentId
    ) {
      throw new Error('tenant_mismatch');
    }
    if (
      !identifierSchema.safeParse(this.trustedTimeContext.bootEpoch).success ||
      !digest64Schema.safeParse(this.trustedTimeContext.checkpointDigest).success
    ) {
      throw new Error('trusted_context_invalid');
    }
    this.assertGenerationContext(this.snapshot.generationContext, this.expectedContext);
    if (this.snapshot.durableCheckpoint.orgId !== this.expectedContext.orgId) {
      throw new Error('tenant_mismatch');
    }
    this.assertCheckpointPins(this.snapshot.durableCheckpoint);
  }

  private assertTrustedTimeContext(context: AciTrustContext): void {
    if (
      context.orgId !== this.trustedTimeContext.orgId ||
      context.deploymentId !== this.trustedTimeContext.deploymentId ||
      context.bootEpoch !== this.trustedTimeContext.bootEpoch ||
      context.checkpointDigest !== this.trustedTimeContext.checkpointDigest
    ) {
      throw new Error('trusted_context_mismatch');
    }
  }

  private async readPinnedCheckpoint() {
    const checkpoint = await this.durable.read(this.expectedContext);
    assertDurableCheckpointAgainstContext(checkpoint, this.expectedContext);
    this.assertCheckpointPins(checkpoint);
    return checkpoint;
  }

  private assertCheckpointPins(
    checkpoint: VerifiedActivePolicySnapshotV1['durableCheckpoint'],
  ): void {
    const pinned = this.snapshot.durableCheckpoint;
    for (const key of [
      'orgId',
      'deploymentId',
      'policyDigest',
      'policyGeneration',
      'activationGeneration',
      'configurationGeneration',
      'keysetEpoch',
      'keysetDigest',
      'releaseId',
      'protectedSourceCommit',
      'eifDigest',
      'pcr0',
      'bootRootDigest',
      'predecessorDigest',
      'checkpointDigest',
      'signerKeyId',
      'signerPurpose',
    ] as const) {
      if (checkpoint[key] !== pinned[key]) throw new Error('checkpoint_not_pinned');
    }
  }

  private assertGenerationContext(
    actual: GenerationContextV1,
    expected: GenerationContextV1,
  ): void {
    for (const key of GENERATION_CONTEXT_FIELDS) {
      if (actual[key] !== expected[key]) throw new Error('generation_context_mismatch');
    }
  }
}
