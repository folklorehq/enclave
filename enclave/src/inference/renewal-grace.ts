import type {
  DurableGenerationHighWaterCheckpointV1,
  GenerationContextV1,
} from '@folklore/contracts';
import type { DurableGenerationHighWaterClientPort } from '@folklore/inference';
import type {
  ChainedGenerationHighWaterCheckpointV1,
  RecentGenerationHighWaterPort,
} from './ports.js';

export const RENEWAL_GRACE_MAX_LINKS = 3;
export const RENEWAL_GRACE_READ_COUNT = RENEWAL_GRACE_MAX_LINKS + 1;

export const GENERATION_CONTEXT_FIELDS = [
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
] as const satisfies readonly (keyof GenerationContextV1)[];

const RENEWAL_STABLE_FIELDS = GENERATION_CONTEXT_FIELDS.filter(
  (field) => field !== 'policyGeneration' && field !== 'policyDigest',
);

export function assertGenerationContextEqual(
  actual: GenerationContextV1,
  expected: GenerationContextV1,
): void {
  for (const field of GENERATION_CONTEXT_FIELDS) {
    if (actual[field] !== expected[field]) throw new Error('active_policy_generation_mismatch');
  }
}

// A head with the installed context, or a bounded renewal of it, keeps the installed one serving.
export function servingCheckpointForInstalled(
  recent: readonly ChainedGenerationHighWaterCheckpointV1[],
  expected: GenerationContextV1,
  installed: DurableGenerationHighWaterCheckpointV1,
): DurableGenerationHighWaterCheckpointV1 {
  const head = recent.at(-1);
  if (!head) throw new Error('active_policy_high_water_missing');
  assertGenerationContextEqual(installed, expected);
  if (sameGenerationContext(head, installed)) {
    assertSameSigner(head, installed);
    assertUnchangedSinceInstalled(recent, installed);
    return installed;
  }
  assertRenewalLinks(linksAfterInstalled(recent, installed), installed);
  return installed;
}

export function installedSnapshotHighWater(
  highWater: RecentGenerationHighWaterPort,
  installed: DurableGenerationHighWaterCheckpointV1,
): DurableGenerationHighWaterClientPort {
  return {
    read: async (context) =>
      servingCheckpointForInstalled(
        await highWater.readRecent(context, RENEWAL_GRACE_READ_COUNT),
        context,
        installed,
      ),
  };
}

function assertUnchangedSinceInstalled(
  recent: readonly ChainedGenerationHighWaterCheckpointV1[],
  installed: DurableGenerationHighWaterCheckpointV1,
): void {
  const installedIndex = installedIndexIn(recent, installed);
  if (installedIndex < 0) return;
  for (const checkpoint of recent.slice(installedIndex + 1)) {
    if (!sameGenerationContext(checkpoint, installed)) {
      throw new Error('active_policy_renewal_grace_context_changed');
    }
    assertSameSigner(checkpoint, installed);
  }
}

function installedIndexIn(
  recent: readonly ChainedGenerationHighWaterCheckpointV1[],
  installed: DurableGenerationHighWaterCheckpointV1,
): number {
  return recent.findIndex(
    (checkpoint) => checkpoint.checkpointDigest === installed.checkpointDigest,
  );
}

function linksAfterInstalled(
  recent: readonly ChainedGenerationHighWaterCheckpointV1[],
  installed: DurableGenerationHighWaterCheckpointV1,
): readonly ChainedGenerationHighWaterCheckpointV1[] {
  const installedIndex = installedIndexIn(recent, installed);
  if (installedIndex < 0) throw new Error('active_policy_renewal_grace_exceeded');
  const anchor = recent[installedIndex];
  if (!anchor || !sameGenerationContext(anchor, installed)) {
    throw new Error('active_policy_renewal_grace_anchor_mismatch');
  }
  assertSameSigner(anchor, installed);
  const links = recent.slice(installedIndex + 1);
  if (links.length === 0 || links.length > RENEWAL_GRACE_MAX_LINKS) {
    throw new Error('active_policy_renewal_grace_exceeded');
  }
  return links;
}

function assertRenewalLinks(
  links: readonly ChainedGenerationHighWaterCheckpointV1[],
  installed: DurableGenerationHighWaterCheckpointV1,
): void {
  const head = links.at(-1);
  if (!head) throw new Error('active_policy_renewal_grace_exceeded');
  let previous: DurableGenerationHighWaterCheckpointV1 = installed;
  for (const link of links) {
    if (link.previousCheckpointDigest !== previous.checkpointDigest) {
      throw new Error('active_policy_renewal_grace_unchained');
    }
    assertSameSigner(link, installed);
    for (const field of RENEWAL_STABLE_FIELDS) {
      if (link[field] !== installed[field]) {
        throw new Error('active_policy_renewal_grace_context_changed');
      }
    }
    if (link.policyGeneration < previous.policyGeneration) {
      throw new Error('active_policy_renewal_grace_generation_regressed');
    }
    if (link.policyDigest !== expectedLinkDigest(link.policyGeneration, installed, head)) {
      throw new Error('active_policy_renewal_grace_digest_conflict');
    }
    previous = link;
  }
}

function expectedLinkDigest(
  generation: number,
  installed: DurableGenerationHighWaterCheckpointV1,
  head: DurableGenerationHighWaterCheckpointV1,
): string {
  if (generation === installed.policyGeneration) return installed.policyDigest;
  if (generation === installed.policyGeneration + 1) return head.policyDigest;
  throw new Error('active_policy_renewal_grace_generation_jump');
}

function sameGenerationContext(
  actual: GenerationContextV1,
  expected: GenerationContextV1,
): boolean {
  return GENERATION_CONTEXT_FIELDS.every((field) => actual[field] === expected[field]);
}

function assertSameSigner(
  actual: DurableGenerationHighWaterCheckpointV1,
  installed: DurableGenerationHighWaterCheckpointV1,
): void {
  if (
    actual.signerKeyId !== installed.signerKeyId ||
    actual.signerPurpose !== installed.signerPurpose
  ) {
    throw new Error('active_policy_signer_mismatch');
  }
}
