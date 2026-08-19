import { createHash } from 'node:crypto';
import {
  controlledGatewayModelArtifactBindingV1Schema,
  policySignedModelProvenanceTupleV1Schema,
  providerNativeModelArtifactBindingV1Schema,
  type ControlledGatewayModelArtifactBindingV1,
  type PolicySignedModelProvenanceTupleV1,
  type ProviderNativeModelArtifactBindingV1,
} from '@folklore/contracts';
import type { InferenceModelRole } from '@folklore/contracts';
import { canonicalCbor } from './canonical-cbor.js';

export const MODEL_PROVENANCE_TUPLE_V1_DOMAIN = 'folklore.model-provenance-tuple.v1';
export const PROVIDER_NATIVE_BINDING_V1_DOMAIN =
  'folklore.provider-native-model-artifact-binding.v1';
export const CONTROLLED_GATEWAY_BINDING_V1_DOMAIN =
  'folklore.controlled-gateway-model-artifact-binding.v1';
export const CONTROLLED_GATEWAY_PROOF_BINDING_V1_DOMAIN =
  'folklore.controlled-gateway-proof-binding.v1';
export const PRE_FORWARD_ROUTE_PROOF_V1_DOMAIN = 'folklore.pre-forward-route-proof.v1';

export interface ControlledGatewayProofBindingV1 {
  readonly schema: 'folklore.controlled-gateway-proof-binding.v1';
  readonly source: 'controlled-gateway';
  readonly orgId: string;
  readonly deploymentId: string;
  readonly tenantId: string;
  readonly assignmentDigest: string;
  readonly proofId: string;
  readonly proofDigest: string;
  readonly requestId: string;
  readonly workloadId: string;
  readonly runtimeIdentityDigest: string;
  readonly workloadArtifactDigest: string;
  readonly pinnedTrustRootDigest: string;
  readonly channelKeyDigest: string;
  readonly exporterLabel: string;
  readonly exporterDigest: string;
  readonly transcriptDigest: string;
  readonly snapshotDigest: string;
  readonly policyDigest: string;
  readonly tenantAadDigest: string;
  readonly capabilityDigest: string;
  readonly origin: string;
  readonly route: string;
  readonly method: 'POST';
  readonly routeIdentityDigest: string;
  readonly role: InferenceModelRole;
  readonly sessionId: string;
  readonly model: string;
  readonly modelRevision: string;
  readonly modelArtifactDigest: string;
  readonly workloadKeysetDigest: string;
  readonly policyGeneration: number;
  readonly activationGeneration: number;
  readonly gatewayNonce: string;
  readonly bootEpoch: string;
  readonly trustedTimeCheckpointDigest: string;
}

// The one shared domain-separated recipe: UTF8(domain) || 0x00 || canonicalCBOR(orderedArray).
export function domainSeparatedBytes(domain: string, array: unknown[]): Uint8Array {
  const domainBytes = Buffer.from(domain, 'utf8');
  const payload = canonicalCbor(array);
  const joined = new Uint8Array(domainBytes.byteLength + 1 + payload.byteLength);
  joined.set(domainBytes, 0);
  joined[domainBytes.byteLength] = 0x00;
  joined.set(payload, domainBytes.byteLength + 1);
  return joined;
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function modelProvenanceTupleFields(tuple: PolicySignedModelProvenanceTupleV1): unknown[] {
  return [
    tuple.schema,
    tuple.orgId,
    tuple.deploymentId,
    tuple.role,
    tuple.modelId,
    tuple.modelRevision,
    tuple.modelArtifactDigest,
  ];
}

export function canonicalModelProvenanceTupleArrayV1(
  input: PolicySignedModelProvenanceTupleV1,
): Uint8Array {
  const tuple = policySignedModelProvenanceTupleV1Schema.parse(input);
  return canonicalCbor(modelProvenanceTupleFields(tuple));
}

export function encodeModelProvenanceTupleV1(
  input: PolicySignedModelProvenanceTupleV1,
): Uint8Array {
  const tuple = policySignedModelProvenanceTupleV1Schema.parse(input);
  return domainSeparatedBytes(MODEL_PROVENANCE_TUPLE_V1_DOMAIN, modelProvenanceTupleFields(tuple));
}

export function digestModelProvenanceTupleV1(input: PolicySignedModelProvenanceTupleV1): string {
  return sha256Hex(encodeModelProvenanceTupleV1(input));
}

function providerNativeBindingFields(binding: ProviderNativeModelArtifactBindingV1): unknown[] {
  return [
    binding.schema,
    binding.source,
    binding.orgId,
    binding.deploymentId,
    binding.role,
    binding.sessionId,
    binding.workloadKeysetDigest,
    binding.modelId,
    binding.modelRevision,
    binding.modelArtifactDigest,
    binding.issuerWorkloadId,
    binding.workloadArtifactDigest,
    binding.nativeEvidenceDigest,
    binding.routeIdentityDigest,
  ];
}

export function canonicalProviderNativeBindingArrayV1(
  input: ProviderNativeModelArtifactBindingV1,
): Uint8Array {
  const binding = providerNativeModelArtifactBindingV1Schema.parse(input);
  return canonicalCbor(providerNativeBindingFields(binding));
}

export function encodeProviderNativeBindingV1(
  input: ProviderNativeModelArtifactBindingV1,
): Uint8Array {
  const binding = providerNativeModelArtifactBindingV1Schema.parse(input);
  return domainSeparatedBytes(
    PROVIDER_NATIVE_BINDING_V1_DOMAIN,
    providerNativeBindingFields(binding),
  );
}

export function digestProviderNativeBindingV1(input: ProviderNativeModelArtifactBindingV1): string {
  return sha256Hex(encodeProviderNativeBindingV1(input));
}

function controlledGatewayBindingFields(
  binding: ControlledGatewayModelArtifactBindingV1,
): unknown[] {
  return [
    binding.schema,
    binding.source,
    binding.orgId,
    binding.deploymentId,
    binding.role,
    binding.proofId,
    binding.requestId,
    binding.sessionId,
    binding.workloadId,
    binding.workloadKeysetDigest,
    binding.modelId,
    binding.modelRevision,
    binding.modelArtifactDigest,
    binding.routeIdentityDigest,
    binding.proofDigest,
    binding.policyGeneration,
    binding.activationGeneration,
  ];
}

export function canonicalControlledGatewayBindingArrayV1(
  input: ControlledGatewayModelArtifactBindingV1,
): Uint8Array {
  const binding = controlledGatewayModelArtifactBindingV1Schema.parse(input);
  return canonicalCbor(controlledGatewayBindingFields(binding));
}

export function encodeControlledGatewayBindingV1(
  input: ControlledGatewayModelArtifactBindingV1,
): Uint8Array {
  const binding = controlledGatewayModelArtifactBindingV1Schema.parse(input);
  return domainSeparatedBytes(
    CONTROLLED_GATEWAY_BINDING_V1_DOMAIN,
    controlledGatewayBindingFields(binding),
  );
}

export function digestControlledGatewayBindingV1(
  input: ControlledGatewayModelArtifactBindingV1,
): string {
  return sha256Hex(encodeControlledGatewayBindingV1(input));
}

function controlledGatewayProofBindingFields(binding: ControlledGatewayProofBindingV1): unknown[] {
  return [
    binding.schema,
    binding.source,
    binding.orgId,
    binding.deploymentId,
    binding.tenantId,
    binding.assignmentDigest,
    binding.proofId,
    binding.proofDigest,
    binding.requestId,
    binding.workloadId,
    binding.runtimeIdentityDigest,
    binding.workloadArtifactDigest,
    binding.pinnedTrustRootDigest,
    binding.channelKeyDigest,
    binding.exporterLabel,
    binding.exporterDigest,
    binding.transcriptDigest,
    binding.snapshotDigest,
    binding.policyDigest,
    binding.tenantAadDigest,
    binding.capabilityDigest,
    binding.origin,
    binding.route,
    binding.method,
    binding.routeIdentityDigest,
    binding.role,
    binding.sessionId,
    binding.model,
    binding.modelRevision,
    binding.modelArtifactDigest,
    binding.workloadKeysetDigest,
    binding.policyGeneration,
    binding.activationGeneration,
    binding.gatewayNonce,
    binding.bootEpoch,
    binding.trustedTimeCheckpointDigest,
  ];
}

function assertControlledGatewayProofBindingWellFormed(
  binding: ControlledGatewayProofBindingV1,
): void {
  if (binding.method !== 'POST') throw new TypeError('invalid controlled proof binding method');
  if (
    !Number.isInteger(binding.policyGeneration) ||
    binding.policyGeneration < 1 ||
    !Number.isInteger(binding.activationGeneration) ||
    binding.activationGeneration < 1
  ) {
    throw new TypeError('invalid controlled proof binding generation');
  }
}

export function canonicalControlledGatewayProofBindingArrayV1(
  input: ControlledGatewayProofBindingV1,
): Uint8Array {
  assertControlledGatewayProofBindingWellFormed(input);
  return canonicalCbor(controlledGatewayProofBindingFields(input));
}

export function encodeControlledGatewayProofBindingV1(
  input: ControlledGatewayProofBindingV1,
): Uint8Array {
  assertControlledGatewayProofBindingWellFormed(input);
  return domainSeparatedBytes(
    CONTROLLED_GATEWAY_PROOF_BINDING_V1_DOMAIN,
    controlledGatewayProofBindingFields(input),
  );
}

export function digestControlledGatewayProofBindingV1(
  input: ControlledGatewayProofBindingV1,
): string {
  return sha256Hex(encodeControlledGatewayProofBindingV1(input));
}

// proofDigest is the lowercase SHA-256 over the exact UTF-8 payload bytes produced by
// `preForwardRouteProofPayload` (UTF8(domain) || 0x00 || canonicalJSON(unsignedProof)).
export function digestPreForwardRouteProofV1(payload: string): string {
  return sha256Hex(Buffer.from(payload, 'utf8'));
}
