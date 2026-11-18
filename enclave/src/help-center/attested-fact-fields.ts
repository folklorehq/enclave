import type { HelpCenterAttestedFactRow } from './ports.js';

export function attestedFactMacFields(
  orgId: string,
  row: Omit<HelpCenterAttestedFactRow, 'mac'>,
): Readonly<Record<string, unknown>> {
  return {
    orgId,
    factId: row.factId,
    bodyHash: row.bodyHash,
    sourceKind: row.sourceKind,
    resourceExternalId: row.resourceExternalId,
    sensitivityLevel: row.sensitivityLevel,
    origin: row.origin,
    ownerAccountId: row.ownerAccountId,
  };
}
