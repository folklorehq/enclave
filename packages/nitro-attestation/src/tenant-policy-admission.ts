import { createHash } from 'node:crypto';
import {
  GENERAL_ADMISSION_ISSUANCE_ID_DOMAIN,
  TENANT_POLICY_ADMISSION_DOMAIN,
  TENANT_POLICY_ADMISSION_MAX_FUTURE_SKEW_MS,
  TENANT_POLICY_ADMISSION_MAX_LIFETIME_MS,
  generalAdmissionIssuanceRecordV1Schema,
  tenantPolicyAdmissionSubjectV1Schema,
  tenantPolicyAdmissionV1Schema,
  type GeneralAdmissionIssuanceRecordV1,
  type TenantPolicyAdmissionSubjectV1,
  type TenantPolicyAdmissionV1,
} from '@folklore/contracts';
import { canonicalCbor } from './canonical-cbor.js';

const DOMAIN_SEPARATOR = Buffer.from(`${TENANT_POLICY_ADMISSION_DOMAIN}\0`, 'utf8');
const GENERAL_ADMISSION_ISSUANCE_ID_DOMAIN_SEPARATOR = Buffer.from(
  `${GENERAL_ADMISSION_ISSUANCE_ID_DOMAIN}\0`,
  'utf8',
);
const TENANT_POLICY_ADMISSION_OBJECT_PREFIX = 'gate-a/tenant-policy-admission/v1';
const TENANT_POLICY_ROLE_CONTEXT_DOMAIN = 'folklore.tenant-policy-role-context.v1';
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

export class TenantPolicyAdmissionTimeError extends Error {
  constructor() {
    super('tenant policy admission time is invalid');
    this.name = 'TenantPolicyAdmissionTimeError';
  }
}

export interface TenantPolicyAdmissionObjectKeyInput {
  readonly orgId: string;
  readonly deploymentId: string;
  readonly poolDeploymentId: string;
  readonly assignmentGeneration: number;
  readonly admissionDigest: string;
}

export function tenantPolicyAdmissionObjectKey(input: TenantPolicyAdmissionObjectKeyInput): string {
  if (
    !PATH_SEGMENT_PATTERN.test(input.orgId) ||
    !PATH_SEGMENT_PATTERN.test(input.deploymentId) ||
    !PATH_SEGMENT_PATTERN.test(input.poolDeploymentId)
  ) {
    throw new Error('tenant_policy_admission_identity_invalid');
  }
  if (
    !Number.isSafeInteger(input.assignmentGeneration) ||
    input.assignmentGeneration <= 0 ||
    !DIGEST_PATTERN.test(input.admissionDigest)
  ) {
    throw new Error('tenant_policy_admission_digest_invalid');
  }
  return `${TENANT_POLICY_ADMISSION_OBJECT_PREFIX}/org/${input.orgId}/deployment/${input.deploymentId}/pool-deployment/${input.poolDeploymentId}/assignment-generation/${input.assignmentGeneration}/admission/${input.admissionDigest}.cbor`;
}

export function deriveGeneralAdmissionWindowV1(trustedTime: Date | number): number {
  const time = trustedTime instanceof Date ? trustedTime.getTime() : trustedTime;
  if (!Number.isFinite(time) || time < 0) {
    throw new Error('general_admission_window_invalid');
  }
  return Math.floor(time / TENANT_POLICY_ADMISSION_MAX_LIFETIME_MS);
}

// A policy lives for an epoch, longer than the admission window, so an epoch's admissions agree.
export const ACTIVE_POLICY_EPOCH_MS = 12 * 60 * 60 * 1_000;
export const ACTIVE_POLICY_VALIDITY_MS = 2 * ACTIVE_POLICY_EPOCH_MS;
export const ACTIVE_POLICY_EPOCH_ORIGIN_MS = Date.UTC(2026, 9, 1);

export interface ActivePolicyEpochV1 {
  readonly policyGeneration: number;
  readonly establishedAtMs: number;
  readonly expiresAtMs: number;
}

/** The policy generation and lifetime of the epoch holding an admission window's start. */
export function deriveActivePolicyEpochV1(
  admissionWindowStart: Date | number,
): ActivePolicyEpochV1 {
  const time =
    admissionWindowStart instanceof Date ? admissionWindowStart.getTime() : admissionWindowStart;
  if (!Number.isFinite(time) || time < ACTIVE_POLICY_EPOCH_ORIGIN_MS) {
    throw new Error('active_policy_epoch_invalid');
  }
  const epochIndex = Math.floor((time - ACTIVE_POLICY_EPOCH_ORIGIN_MS) / ACTIVE_POLICY_EPOCH_MS);
  const establishedAtMs = ACTIVE_POLICY_EPOCH_ORIGIN_MS + epochIndex * ACTIVE_POLICY_EPOCH_MS;
  return {
    policyGeneration: epochIndex + 1,
    establishedAtMs,
    expiresAtMs: establishedAtMs + ACTIVE_POLICY_VALIDITY_MS,
  };
}

export function deriveGeneralAdmissionWindowStartV1(admissionWindow: number): Date {
  if (!Number.isSafeInteger(admissionWindow) || admissionWindow < 0) {
    throw new Error('general_admission_window_invalid');
  }
  return new Date(admissionWindow * TENANT_POLICY_ADMISSION_MAX_LIFETIME_MS);
}

export function deriveGeneralAdmissionWindowEndV1(admissionWindow: number): Date {
  return new Date(
    deriveGeneralAdmissionWindowStartV1(admissionWindow).getTime() +
      TENANT_POLICY_ADMISSION_MAX_LIFETIME_MS,
  );
}

export function computeGeneralAdmissionIssuanceIdV1(
  input: Omit<GeneralAdmissionIssuanceRecordV1, 'issuanceId'>,
): string {
  const subject = generalAdmissionIssuanceRecordV1Schema.omit({ issuanceId: true }).parse(input);
  return createHash('sha256')
    .update(GENERAL_ADMISSION_ISSUANCE_ID_DOMAIN_SEPARATOR)
    .update(canonicalCbor(subject))
    .digest('hex');
}

export function encodeTenantPolicyAdmissionSubjectV1(
  subject: TenantPolicyAdmissionSubjectV1,
): Uint8Array {
  return canonicalCbor(tenantPolicyAdmissionSubjectV1Schema.parse(subject));
}

export function computeTenantPolicyAdmissionDigestV1(
  subject: TenantPolicyAdmissionSubjectV1,
): string {
  return createHash('sha256').update(encodeTenantPolicyAdmissionSubjectV1(subject)).digest('hex');
}

export function computeTenantPolicyRoleContextDigestV1(
  subject: TenantPolicyAdmissionSubjectV1,
  role: keyof TenantPolicyAdmissionSubjectV1['approvedPolicyTemplate']['roles'],
): string {
  const parsed = tenantPolicyAdmissionSubjectV1Schema.parse(subject);
  if (!(role in parsed.approvedPolicyTemplate.roles)) {
    throw new Error('tenant_policy_role_context_invalid');
  }
  return createHash('sha256')
    .update(Buffer.from(`${TENANT_POLICY_ROLE_CONTEXT_DOMAIN}\0`, 'utf8'))
    .update(
      canonicalCbor({
        orgId: parsed.orgId,
        deploymentId: parsed.deploymentId,
        poolDeploymentId: parsed.poolDeploymentId,
        assignmentGeneration: parsed.assignmentGeneration,
        policyGeneration: parsed.policyGeneration,
        activationGeneration: parsed.activationGeneration,
        configurationGeneration: parsed.configurationGeneration,
        releaseId: parsed.releaseId,
        role,
      }),
    )
    .digest('hex');
}

export function tenantPolicyAdmissionSignatureInputV1(
  admission: TenantPolicyAdmissionV1,
): Uint8Array {
  const parsed = tenantPolicyAdmissionV1Schema.parse(admission);
  if (parsed.admissionDigest !== computeTenantPolicyAdmissionDigestV1(parsed.subject)) {
    throw new Error('tenant_policy_admission_digest_mismatch');
  }
  const digest = createHash('sha256').update(canonicalCbor(parsed)).digest();
  return Buffer.concat([DOMAIN_SEPARATOR, digest]);
}

export function verifyTenantPolicyAdmissionTimeV1(
  subject: TenantPolicyAdmissionSubjectV1,
  trustedNow: Date,
): void {
  const parsed = tenantPolicyAdmissionSubjectV1Schema.parse(subject);
  const issuedAt = Date.parse(parsed.issuedAt);
  const expiresAt = Date.parse(parsed.expiresAt);
  const now = trustedNow.getTime();
  const duration = expiresAt - issuedAt;
  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    !Number.isFinite(now) ||
    issuedAt - now > TENANT_POLICY_ADMISSION_MAX_FUTURE_SKEW_MS ||
    issuedAt > now ||
    now >= expiresAt ||
    duration <= 0 ||
    duration > TENANT_POLICY_ADMISSION_MAX_LIFETIME_MS
  ) {
    throw new TenantPolicyAdmissionTimeError();
  }
}
