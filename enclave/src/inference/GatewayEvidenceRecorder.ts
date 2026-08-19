import {
  finalCommitMarkerPayloadV1,
  gatewayEvidenceRecordRequestV2Schema,
  releaseProvenancePayloadV1,
  type Digest64,
  type EvidenceRecorderPort,
  type GatewayEvidenceRecordRequestV2,
  type ReleaseProvenanceContextV1,
  type UnsignedReleaseProvenanceBindingV1,
} from '@folklore/contracts';
import { canonicalJson, sha256Hex } from '@folklore/utils';
import {
  EVIDENCE_ANCHOR_CBOR_VERSION,
  EVIDENCE_ANCHOR_DOMAIN_CODE,
  EVIDENCE_ANCHOR_PURPOSE_CODE,
  encodeEvidenceAnchorCbor,
} from '../sealing/nsm.js';
import type { EvidenceAnchorVerifier } from './EvidenceAnchorVerifier.js';
import {
  typedGatewayEvidenceSignedV2Schema,
  type EvidenceKeySession,
  type TypedGatewayEvidenceUnsignedV2,
} from './EvidenceKeySession.js';
import {
  trustedEvidenceContextDigestV1,
  type TrustedEvidenceContextProvider,
  type TrustedEvidenceContextV1,
} from './TrustedEvidenceContextProvider.js';

export type GatewayEvidenceRecorderErrorCode =
  | 'recording_boundary_violation'
  | 'release_provenance_digest_mismatch'
  | 'final_commit_marker_mismatch'
  | 'nonce_replay'
  | 'evidence_anchor_invalid'
  | 'evidence_session_unavailable'
  | 'evidence_composition_incomplete';

export class GatewayEvidenceRecorderError extends Error {
  readonly code: GatewayEvidenceRecorderErrorCode;

  constructor(code: GatewayEvidenceRecorderErrorCode) {
    super(code);
    this.name = 'GatewayEvidenceRecorderError';
    this.code = code;
  }
}

// The only production evidence recorder (PR5). The caller supplies only a content-free run id, a
// fresh nonce, and a release receipt already verified by the in-enclave release verifier. Trusted
// context comes from the verified-boot provider; the evidence anchor is bound to that context and
// the request nonce; the typed session signs a typed unsigned envelope, never bytes, purpose, or
// a key id. Raw NSM documents, wire bytes, receipt ids, proof ids, and customer content never
// leave enclave memory.
export class GatewayEvidenceRecorder implements EvidenceRecorderPort {
  readonly #provider: TrustedEvidenceContextProvider;
  readonly #anchorVerifier: EvidenceAnchorVerifier;
  readonly #keySession: EvidenceKeySession;
  readonly #usedNonceDigests = new Set<string>();

  constructor(
    provider: TrustedEvidenceContextProvider,
    anchorVerifier: EvidenceAnchorVerifier,
    keySession: EvidenceKeySession,
  ) {
    if (!provider || !anchorVerifier || !keySession) {
      throw new GatewayEvidenceRecorderError('evidence_composition_incomplete');
    }
    this.#provider = provider;
    this.#anchorVerifier = anchorVerifier;
    this.#keySession = keySession;
  }

  async record(input: GatewayEvidenceRecordRequestV2): Promise<{
    evidenceDigest: Digest64;
    state: 'recorded';
  }> {
    const parsed = gatewayEvidenceRecordRequestV2Schema.safeParse(input);
    if (!parsed.success) {
      throw new GatewayEvidenceRecorderError('recording_boundary_violation');
    }
    const request = parsed.data;
    const context = this.#provider.current();
    this.verifyReleaseReceipt(request, context);
    this.claimNonce(request.nonce);
    const anchor = this.buildAnchor(context, request.nonce);
    this.#anchorVerifier.verify(anchor, context);
    const unsignedEnvelope = this.buildUnsignedEnvelope(request, context);
    let signed;
    try {
      signed = await this.#keySession.signEvidence({ envelope: unsignedEnvelope });
    } catch {
      throw new GatewayEvidenceRecorderError('evidence_session_unavailable');
    }
    const validatedEnvelope = typedGatewayEvidenceSignedV2Schema.safeParse(signed);
    if (!validatedEnvelope.success) {
      throw new GatewayEvidenceRecorderError('recording_boundary_violation');
    }
    return {
      evidenceDigest: sha256Hex(canonicalJson(validatedEnvelope.data)),
      state: 'recorded',
    };
  }

  private verifyReleaseReceipt(
    request: GatewayEvidenceRecordRequestV2,
    context: TrustedEvidenceContextV1,
  ): void {
    const receipt = request.releaseReceipt;
    const releaseContext: ReleaseProvenanceContextV1 = {
      orgId: context.orgId,
      deploymentId: context.deploymentId,
      releaseId: context.releaseId,
      protectedSourceCommit: context.protectedSourceCommit,
      eifArtifactPath: context.eifArtifactPath,
      eifDigest: context.eifDigest,
      pcr0: context.pcr0,
      bootRootDigest: context.bootRootDigest,
      policyDigest: context.policyDigest,
      policyGeneration: context.policyGeneration,
      activationGeneration: context.activationGeneration,
      keysetHighWaterEpoch: context.keysetHighWaterEpoch,
      keysetHighWaterDigest: context.keysetHighWaterDigest,
    };
    const binding: UnsignedReleaseProvenanceBindingV1 = {
      protectedSourceCommit: context.protectedSourceCommit,
      eifArtifactPath: context.eifArtifactPath,
      eifDigest: context.eifDigest,
      pcr0: context.pcr0,
      bootRootDigest: context.bootRootDigest,
      deploymentId: context.deploymentId,
      runtimeIdentityDigest: this.digestValue(context, 'runtimeIdentityDigest'),
      recipientKmsReceiptDigest: this.digestValue(context, 'recipientKmsReceiptDigest'),
      assignmentAcknowledgmentDigest: this.digestValue(context, 'assignmentAcknowledgmentDigest'),
      routeProofDigest: this.digestValue(context, 'routeProofDigest'),
      admissionProofDigest: this.digestValue(context, 'admissionProofDigest'),
      queueChecksDigest: this.digestValue(context, 'queueChecksDigest'),
      dlqChecksDigest: this.digestValue(context, 'dlqChecksDigest'),
      aciReportSignatureDigest: this.digestValue(context, 'aciReportSignatureDigest'),
    };
    const expectedReleaseProvenanceDigest = sha256Hex(
      canonicalJson(releaseProvenancePayloadV1({ context: releaseContext, binding })),
    );
    const expectedFinalCommitMarker = sha256Hex(
      canonicalJson(
        finalCommitMarkerPayloadV1({
          context: releaseContext,
          binding,
          releaseProvenanceDigest: expectedReleaseProvenanceDigest,
        }),
      ),
    );
    if (
      receipt.releaseId !== context.releaseId ||
      receipt.releaseProvenanceDigest !== expectedReleaseProvenanceDigest ||
      receipt.releaseProvenanceDigest !== context.releaseProvenanceDigest
    ) {
      throw new GatewayEvidenceRecorderError('release_provenance_digest_mismatch');
    }
    if (
      receipt.finalCommitMarker !== expectedFinalCommitMarker ||
      receipt.finalCommitMarker !== context.finalCommitMarker
    ) {
      throw new GatewayEvidenceRecorderError('final_commit_marker_mismatch');
    }
  }

  private claimNonce(nonce: Uint8Array): void {
    const digest = sha256Hex(Buffer.from(nonce));
    if (this.#usedNonceDigests.has(digest)) {
      throw new GatewayEvidenceRecorderError('nonce_replay');
    }
    this.#usedNonceDigests.add(digest);
  }

  private buildAnchor(context: TrustedEvidenceContextV1, nonce: Uint8Array): Uint8Array {
    return encodeEvidenceAnchorCbor({
      version: EVIDENCE_ANCHOR_CBOR_VERSION,
      purposeCode: EVIDENCE_ANCHOR_PURPOSE_CODE,
      domainCode: EVIDENCE_ANCHOR_DOMAIN_CODE,
      contextDigest: trustedEvidenceContextDigestV1(context),
      orgId: context.orgId,
      deploymentId: context.deploymentId,
      sessionId: context.sessionId,
      bootEpoch: context.bootEpoch,
      policyGeneration: context.policyGeneration,
      keysetHighWaterEpoch: context.keysetHighWaterEpoch,
      keysetHighWaterDigest: context.keysetHighWaterDigest,
      nonce: Uint8Array.from(nonce),
    });
  }

  private buildUnsignedEnvelope(
    request: GatewayEvidenceRecordRequestV2,
    context: TrustedEvidenceContextV1,
  ): TypedGatewayEvidenceUnsignedV2 {
    return {
      schema: 'GatewayEvidenceEnvelopeV2',
      canonicalDomain: 'folklore.aci-gateway-evidence.v1',
      orgId: context.orgId,
      deploymentId: context.deploymentId,
      releaseId: context.releaseId,
      protectedSourceCommit: context.protectedSourceCommit,
      eifArtifactPath: context.eifArtifactPath,
      eifDigest: context.eifDigest,
      pcr0: context.pcr0,
      bootRootDigest: context.bootRootDigest,
      values: context.values,
      runId: request.runId,
      nonceDigest: sha256Hex(Buffer.from(request.nonce)),
      releaseReceiptDigest: sha256Hex(canonicalJson(request.releaseReceipt)),
    };
  }

  private digestValue(context: TrustedEvidenceContextV1, key: string): Digest64 {
    const value = context.values[key];
    if (!value || value.kind !== 'digest') {
      throw new GatewayEvidenceRecorderError('recording_boundary_violation');
    }
    return value.value;
  }
}
