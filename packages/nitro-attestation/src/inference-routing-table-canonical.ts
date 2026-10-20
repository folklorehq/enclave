import { inferenceRoutingTableV1Schema, type InferenceRoutingTableV1 } from '@folklore/contracts';
import { canonicalCbor } from './canonical-cbor.js';
import { domainSeparatedDigest, sha256Hex } from './model-provenance-canonical.js';

export const INFERENCE_ROUTING_TABLE_V1_DOMAIN = 'folklore.inference-routing-table.v1';

function encodeInferenceRoutingTableV1(table: InferenceRoutingTableV1): Uint8Array {
  return canonicalCbor(inferenceRoutingTableV1Schema.parse(table));
}

export function inferenceRoutingTableSignatureInputV1(table: InferenceRoutingTableV1): Uint8Array {
  return domainSeparatedDigest(
    INFERENCE_ROUTING_TABLE_V1_DOMAIN,
    encodeInferenceRoutingTableV1(table),
  );
}

export function digestInferenceRoutingTableV1(table: InferenceRoutingTableV1): string {
  return sha256Hex(encodeInferenceRoutingTableV1(table));
}
