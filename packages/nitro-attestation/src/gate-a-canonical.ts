import { createHash } from 'node:crypto';

import { encode, rfc8949EncodeOptions } from 'cborg';
import {
  gateAWrapperEnvelopeV1Schema,
  gateAWrapperSigningMaterialV1Schema,
  type GateAWrapperSigningMaterialV1,
  type GateAWrapperV1,
} from '@folklore/contracts';

export const GATE_A_WRAPPER_CANONICAL_DOMAIN = 'folklore.gate-a-wrapper.v1';

export function encodeGateAWrapperV1(wrapper: GateAWrapperV1): Uint8Array {
  const parsed = gateAWrapperEnvelopeV1Schema.parse(wrapper);
  return encode([GATE_A_WRAPPER_CANONICAL_DOMAIN, 'full', parsed], rfc8949EncodeOptions);
}

export function encodeGateAWrapperSigningInputV1(wrapper: GateAWrapperV1): Uint8Array {
  const parsed = gateAWrapperEnvelopeV1Schema.parse(wrapper);
  const { artifactDigest: _artifactDigest, signer, ...rest } = parsed;
  const { signature: _signature, ...signerWithoutSignature } = signer;
  return encodeGateAWrapperSigningMaterialV1({
    ...rest,
    signer: signerWithoutSignature,
  });
}

export function encodeGateAWrapperSigningMaterialV1(
  input: GateAWrapperSigningMaterialV1,
): Uint8Array {
  const parsed = gateAWrapperSigningMaterialV1Schema.parse(input);
  return encode([GATE_A_WRAPPER_CANONICAL_DOMAIN, 'signed-material', parsed], rfc8949EncodeOptions);
}

export function digestGateAWrapperV1(wrapper: GateAWrapperV1): string {
  const parsed = gateAWrapperEnvelopeV1Schema.parse(wrapper);
  const { artifactDigest: _artifactDigest, ...withoutArtifactDigest } = parsed;
  return digestGateAWrapperWithoutArtifactDigestV1(withoutArtifactDigest);
}

export function digestGateAWrapperWithoutArtifactDigestV1(
  wrapper: Omit<GateAWrapperV1, 'artifactDigest'>,
): string {
  const { signer, ...rest } = wrapper;
  const { signature: _signature, ...signerWithKeyId } = signer;
  const bytes = encode(
    [GATE_A_WRAPPER_CANONICAL_DOMAIN, 'artifact-digest', { ...rest, signer: signerWithKeyId }],
    rfc8949EncodeOptions,
  );
  return createHash('sha256').update(bytes).digest('hex');
}
