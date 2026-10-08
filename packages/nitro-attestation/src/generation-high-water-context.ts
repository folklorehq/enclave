import type { GenerationContextV1, HighWaterLogEntryV1 } from '@folklore/contracts';

// The canonical keyset fields are the authority; the legacy keyset pair is not read here.
export function generationHighWaterEntryContextV1(
  entry: Pick<HighWaterLogEntryV1, 'checkpoint'>,
): GenerationContextV1 {
  const checkpoint = entry.checkpoint;
  return {
    orgId: checkpoint.orgId,
    deploymentId: checkpoint.deploymentId,
    policyDigest: checkpoint.policyDigest,
    policyGeneration: checkpoint.policyGeneration,
    activationGeneration: checkpoint.activationGeneration,
    configurationGeneration: checkpoint.configurationGeneration,
    keysetEpoch: checkpoint.keysetEpoch,
    keysetDigest: checkpoint.keysetDigest,
    releaseId: checkpoint.releaseId,
    protectedSourceCommit: checkpoint.protectedSourceCommit,
    eifDigest: checkpoint.eifDigest,
    pcr0: checkpoint.pcr0,
    bootRootDigest: checkpoint.bootRootDigest,
  };
}
