import {
  EVIDENCE_ANCHOR_CBOR_VERSION,
  EVIDENCE_ANCHOR_DOMAIN_CODE,
  EVIDENCE_ANCHOR_PURPOSE_CODE,
  decodeEvidenceAnchorCbor,
  type EvidenceAnchorCborFields,
} from '../sealing/nsm.js';
import {
  trustedEvidenceContextDigestV1,
  type TrustedEvidenceContextV1,
} from './TrustedEvidenceContextProvider.js';

export type VerifiedEvidenceAnchorV1 = EvidenceAnchorCborFields & {
  readonly version: 1;
  readonly purposeCode: 1;
  readonly domainCode: 1;
};

export type EvidenceAnchorVerifierErrorCode =
  | 'evidence_anchor_invalid'
  | 'evidence_anchor_purpose_mismatch'
  | 'evidence_anchor_context_mismatch'
  | 'evidence_anchor_stale_boot_epoch';

export class EvidenceAnchorVerifierError extends Error {
  readonly code: EvidenceAnchorVerifierErrorCode;

  constructor(code: EvidenceAnchorVerifierErrorCode) {
    super(code);
    this.name = 'EvidenceAnchorVerifierError';
    this.code = code;
  }
}

// Pure verifier: recomputes the context digest, binds org and deployment, checks boot
// epoch, policy generation, keyset high-water, and rejects an anchor copied across sessions or
// tenants. The trusted context comes from the verified-boot provider, never from request input.
export class EvidenceAnchorVerifier {
  verify(anchor: Uint8Array, context: TrustedEvidenceContextV1): VerifiedEvidenceAnchorV1 {
    let fields: EvidenceAnchorCborFields;
    try {
      fields = decodeEvidenceAnchorCbor(anchor);
    } catch {
      throw new EvidenceAnchorVerifierError('evidence_anchor_invalid');
    }
    if (
      fields.version !== EVIDENCE_ANCHOR_CBOR_VERSION ||
      fields.purposeCode !== EVIDENCE_ANCHOR_PURPOSE_CODE ||
      fields.domainCode !== EVIDENCE_ANCHOR_DOMAIN_CODE
    ) {
      throw new EvidenceAnchorVerifierError('evidence_anchor_purpose_mismatch');
    }
    if (fields.contextDigest !== trustedEvidenceContextDigestV1(context)) {
      throw new EvidenceAnchorVerifierError('evidence_anchor_context_mismatch');
    }
    if (fields.orgId !== context.orgId || fields.deploymentId !== context.deploymentId) {
      throw new EvidenceAnchorVerifierError('evidence_anchor_context_mismatch');
    }
    if (fields.sessionId !== context.sessionId) {
      throw new EvidenceAnchorVerifierError('evidence_anchor_context_mismatch');
    }
    if (fields.bootEpoch !== context.bootEpoch) {
      throw new EvidenceAnchorVerifierError('evidence_anchor_stale_boot_epoch');
    }
    if (
      fields.policyGeneration !== context.policyGeneration ||
      fields.keysetHighWaterEpoch !== context.keysetHighWaterEpoch ||
      fields.keysetHighWaterDigest !== context.keysetHighWaterDigest
    ) {
      throw new EvidenceAnchorVerifierError('evidence_anchor_context_mismatch');
    }
    return Object.freeze({
      ...fields,
      version: 1,
      purposeCode: 1,
      domainCode: 1,
    });
  }
}
