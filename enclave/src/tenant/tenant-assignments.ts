import {
  type NormalizedAssignmentManifestV1,
  type TenantAssignment,
  type VersionedTenantAssignment,
  canonicalQueueUrlSchema,
  parseAssignmentManifestWire as parseContractAssignmentManifestWire,
  tenantBucketNames,
  tenantResourceName,
  tenantWebhookQueueName,
  versionedTenantAssignmentSchema,
} from '@folklore/contracts';
import { isLowercaseRfcUuid } from '@folklore/utils';
import { bareKmsKeyId } from '../sealing/kms-key-arn.js';

// The assignment shape is defined once in the shared contracts so the control-plane producer and
// this consumer cannot drift.

/** Explicit bootstrap compatibility boundary for unsigned legacy assignment sources. */
export function toInitialStorageKeyVersion(
  assignment: TenantAssignment,
  defaultDeploymentId = '',
): VersionedTenantAssignment {
  return versionedTenantAssignmentSchema.parse({
    ...assignment,
    deploymentId: assignment.deploymentId ?? (defaultDeploymentId || assignment.tenantId),
    activeStorageKeyVersion: 1,
    storageKeyHistory: [{ version: 1, storageKeyId: assignment.storageKeyId }],
  });
}

const SQS_URL_PATTERN = /^https:\/\/sqs\.([^.]+)\.amazonaws\.com\/(\d{12})\/([^/]+)$/;

const ASSIGNMENT_MANIFEST_RESOURCE_SHARED = 'assignment_manifest_resource_shared';
const ASSIGNMENT_MANIFEST_RESOURCE_NAME_MISMATCH = 'assignment_manifest_resource_name_mismatch';

/** Parses the signed assignment wire with the same parser as every other reader. */
export function parseAssignmentManifestWire(
  manifest: unknown,
  expectedPoolId: string,
  lastGeneration: number,
): NormalizedAssignmentManifestV1 {
  const parsed = parseContractAssignmentManifestWire(manifest, expectedPoolId, {
    lastGeneration,
  });
  assertNoDuplicates(parsed.assignments);
  return parsed;
}

function assertNoDuplicates(assignments: readonly { tenantId: string }[]): void {
  const seen = new Set<string>();
  for (const assignment of assignments) {
    if (seen.has(assignment.tenantId)) {
      throw new Error(`duplicate tenant assignment for ${assignment.tenantId}`);
    }
    seen.add(assignment.tenantId);
  }
}

type SharedResourceAssignment = TenantAssignment & {
  readonly storageKeyHistory?: readonly { readonly storageKeyId: string }[];
};

// Run on a verified manifest only: a refusal is recorded for signed bytes, never for unsigned ones.
export function assertNoSharedResources(assignments: readonly SharedResourceAssignment[]): void {
  const keyOwners = new Map<string, string>();
  const bucketOwners = new Map<string, string>();
  const queueOwners = new Map<string, string>();
  for (const assignment of assignments) {
    const { tenantId } = assignment;
    claimResources(keyOwners, tenantId, [
      ...[assignment.kmsKeyId, assignment.storageKeyId].map(bareKmsKeyId),
      ...(assignment.storageKeyHistory ?? []).map((entry) => bareKmsKeyId(entry.storageKeyId)),
    ]);
    claimResources(
      bucketOwners,
      tenantId,
      [assignment.sealedBlobBucket, assignment.rawPayloadsBucket, assignment.processedBucket].map(
        (bucket) => bucket.trim(),
      ),
    );
    claimResources(queueOwners, tenantId, [assignment.queueUrl.trim()]);
  }
}

// Buckets and the webhook queue are named from the tenant id by the shared render. KMS key ids are
// random, so they are bound by the org encryption-context condition of the rootless key policy
// (PR #5158) and are otherwise only checked for sharing above. A V4 manifest also fixes the queue's
// account and region to its signed scope.
export function assertAssignmentResourceNamesMatchTenants(
  assignments: readonly TenantAssignment[],
  scope?: { readonly awsAccountId: string; readonly awsRegion: string },
): void {
  for (const assignment of assignments) {
    const { tenantId } = assignment;
    const buckets = tenantBucketNames(tenantResourceName(tenantId));
    const queue = canonicalQueueUrlSchema.safeParse(assignment.queueUrl).success
      ? SQS_URL_PATTERN.exec(assignment.queueUrl)
      : null;
    if (
      !isLowercaseRfcUuid(tenantId) ||
      assignment.sealedBlobBucket !== buckets.sealedBlobs ||
      assignment.rawPayloadsBucket !== buckets.rawPayloads ||
      assignment.processedBucket !== buckets.processed ||
      queue === null ||
      queue[3] !== tenantWebhookQueueName(tenantId) ||
      (scope !== undefined && (queue[1] !== scope.awsRegion || queue[2] !== scope.awsAccountId))
    ) {
      throw new Error(ASSIGNMENT_MANIFEST_RESOURCE_NAME_MISMATCH);
    }
  }
}

function claimResources(
  owners: Map<string, string>,
  tenantId: string,
  resources: readonly string[],
): void {
  for (const resource of resources) {
    const owner = owners.get(resource);
    if (owner !== undefined && owner !== tenantId) {
      throw new Error(ASSIGNMENT_MANIFEST_RESOURCE_SHARED);
    }
    owners.set(resource, tenantId);
  }
}
