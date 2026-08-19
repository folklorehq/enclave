/* eslint-disable @folklore/filename-matches-export -- primary export is the EvidenceKeySession
   port interface and the filename is mandated by the custody plan. */
import { z } from 'zod';
import {
  base64Ed25519SignatureSchema,
  typedGatewayEvidenceValuesSchema,
  type Digest64,
  type TypedGatewayEvidenceValuesV1,
} from '@folklore/contracts';

const identifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const digest64Schema = z.string().regex(/^[0-9a-f]{64}$/);
const gitCommitSchema = z.string().regex(/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/);
const measurement96Schema = z.string().regex(/^[0-9a-f]{96}$/);
const eifArtifactPathSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(/^artifacts\/[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*\.eif$/);

// The typed evidence envelope crossing the in-enclave signing boundary (PR5). It contains the
// recorder-produced schema, context fields, trusted values, run id, nonce digest, and verified
// release receipt digest. It never contains Uint8Array, a purpose, a key id, or a caller digest.
export interface TypedGatewayEvidenceUnsignedV2 {
  schema: 'GatewayEvidenceEnvelopeV2';
  canonicalDomain: 'folklore.aci-gateway-evidence.v1';
  orgId: string;
  deploymentId: string;
  releaseId: string;
  protectedSourceCommit: string;
  eifArtifactPath: string;
  eifDigest: Digest64;
  pcr0: string;
  bootRootDigest: Digest64;
  values: TypedGatewayEvidenceValuesV1;
  runId: string;
  nonceDigest: Digest64;
  releaseReceiptDigest: Digest64;
}

export interface TypedGatewayEvidenceSignedV2 extends TypedGatewayEvidenceUnsignedV2 {
  signerPurpose: 'evidence-envelope';
  signerKeyId: string;
  signature: string;
}

const typedGatewayEvidenceV2Fields = {
  schema: z.literal('GatewayEvidenceEnvelopeV2'),
  canonicalDomain: z.literal('folklore.aci-gateway-evidence.v1'),
  orgId: identifierSchema,
  deploymentId: identifierSchema,
  releaseId: identifierSchema,
  protectedSourceCommit: gitCommitSchema,
  eifArtifactPath: eifArtifactPathSchema,
  eifDigest: digest64Schema,
  pcr0: measurement96Schema,
  bootRootDigest: digest64Schema,
  values: typedGatewayEvidenceValuesSchema,
  runId: identifierSchema,
  nonceDigest: digest64Schema,
  releaseReceiptDigest: digest64Schema,
} as const;

function refineEvidenceEnvelope(
  envelope: { orgId: string; deploymentId: string },
  context: z.RefinementCtx,
): void {
  if (envelope.orgId === envelope.deploymentId) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['deploymentId'],
      message: 'organization and deployment identifiers must be distinct',
    });
  }
}

export const typedGatewayEvidenceUnsignedV2Schema = z
  .object(typedGatewayEvidenceV2Fields)
  .strict()
  .superRefine(refineEvidenceEnvelope);

export const typedGatewayEvidenceSignedV2Schema = z
  .object({
    ...typedGatewayEvidenceV2Fields,
    signerPurpose: z.literal('evidence-envelope'),
    signerKeyId: identifierSchema,
    signature: base64Ed25519SignatureSchema,
  })
  .strict()
  .superRefine(refineEvidenceEnvelope);

export type EvidenceKeySessionErrorCode = 'evidence_session_aborted' | 'evidence_envelope_invalid';

export class EvidenceKeySessionError extends Error {
  readonly code: EvidenceKeySessionErrorCode;

  constructor(code: EvidenceKeySessionErrorCode) {
    super(code);
    this.name = 'EvidenceKeySessionError';
    this.code = code;
  }
}

// Typed in-enclave evidence signing port (PR5): the session chooses the evidence purpose and key
// internally and returns the signer-owned metadata. No production KMS evidence key is created by
// PR1 through PR6; the live session is unavailable until H4 and the later activation gate.
export interface EvidenceKeySession {
  signEvidence(input: {
    envelope: TypedGatewayEvidenceUnsignedV2;
    signal?: AbortSignal;
  }): Promise<TypedGatewayEvidenceSignedV2>;
}
