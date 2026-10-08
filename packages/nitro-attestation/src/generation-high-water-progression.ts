import type { GenerationContextV1 } from '@folklore/contracts';

export type GenerationHighWaterProgressionV1 =
  | 'same-release'
  | 'release-transition'
  | 'context-mismatch'
  | 'lower-generation'
  | 'equal-generation-conflict';

export type GenerationHighWaterReleaseFieldsV1 = Pick<
  GenerationContextV1,
  'releaseId' | 'protectedSourceCommit' | 'eifDigest' | 'pcr0'
>;

const RELEASE_KEY_SEPARATOR = '\u0000';
const GENERATION_FIELDS = [
  'policyGeneration',
  'activationGeneration',
  'configurationGeneration',
  'keysetEpoch',
] as const;

export function generationHighWaterReleaseKeyV1(
  fields: GenerationHighWaterReleaseFieldsV1,
): string {
  // PCR0 is hex, so its letter case carries no identity.
  return [
    fields.releaseId,
    fields.protectedSourceCommit,
    fields.eifDigest,
    fields.pcr0.toLowerCase(),
  ].join(RELEASE_KEY_SEPARATOR);
}

// Classifies one consecutive pair of a chain; the first matching rule wins.
export function classifyGenerationHighWaterProgressionV1(
  previous: GenerationContextV1,
  next: GenerationContextV1,
): GenerationHighWaterProgressionV1 {
  if (!sameChainIdentity(previous, next)) return 'context-mismatch';
  if (anyGenerationMayHaveFallen(previous, next)) return 'lower-generation';
  if (previous.keysetEpoch === next.keysetEpoch && previous.keysetDigest !== next.keysetDigest) {
    return 'equal-generation-conflict';
  }
  const samePolicyGeneration = previous.policyGeneration === next.policyGeneration;
  if (generationHighWaterReleaseKeyV1(previous) === generationHighWaterReleaseKeyV1(next)) {
    if (samePolicyGeneration && previous.policyDigest !== next.policyDigest) {
      return 'equal-generation-conflict';
    }
    return 'same-release';
  }
  if (samePolicyGeneration && !onlyPolicyDigestMayMove(previous, next)) {
    return 'equal-generation-conflict';
  }
  return 'release-transition';
}

// A chain leaves a release only forward: a release it has left never reappears.
export function generationHighWaterReleaseReenteredV1(
  releases: readonly GenerationHighWaterReleaseFieldsV1[],
): boolean {
  const left = new Set<string>();
  let current: string | undefined;
  for (const release of releases) {
    const key = generationHighWaterReleaseKeyV1(release);
    if (key === current) continue;
    if (left.has(key)) return true;
    if (current !== undefined) left.add(current);
    current = key;
  }
  return false;
}

function sameChainIdentity(previous: GenerationContextV1, next: GenerationContextV1): boolean {
  return (
    previous.orgId === next.orgId &&
    previous.deploymentId === next.deploymentId &&
    previous.bootRootDigest === next.bootRootDigest
  );
}

// A generation that is not a safe integer compares false both ways, so it could hide a fall.
function anyGenerationMayHaveFallen(
  previous: GenerationContextV1,
  next: GenerationContextV1,
): boolean {
  return GENERATION_FIELDS.some(
    (field) =>
      !Number.isSafeInteger(previous[field]) ||
      !Number.isSafeInteger(next[field]) ||
      next[field] < previous[field],
  );
}

// Within one policy generation a release change may move the policy digest and nothing else.
function onlyPolicyDigestMayMove(
  previous: GenerationContextV1,
  next: GenerationContextV1,
): boolean {
  return (
    previous.activationGeneration === next.activationGeneration &&
    previous.configurationGeneration === next.configurationGeneration &&
    previous.keysetEpoch === next.keysetEpoch
  );
}
