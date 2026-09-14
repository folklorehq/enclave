import { z } from 'zod';
import {
  durableGenerationHighWaterCheckpointSchema,
  typedGatewayEvidenceValuesSchema,
  type Digest64,
  type EvidenceValueV1,
  type TypedGatewayEvidenceValuesV1,
} from '@folklore/contracts';
import type { VerifiedActivePolicySnapshotV1 } from '@folklore/inference';
import { canonicalJson, sha256Hex } from '@folklore/utils';
import type { VerifiedBootManifest } from '../attestation/BootManifestVerifier.js';

// The accepted floor snapshot wire shape: the durable high-water checkpoint including the legacy
// keyset high-water fields the release-provenance context still serializes.
export type TrustedFloorSnapshotV1 = z.infer<typeof durableGenerationHighWaterCheckpointSchema>;

export interface TrustedEvidenceSessionStateV1 {
  readonly sessionId: string;
  readonly bootEpoch: number;
}

export interface TrustedReleaseStateV1 {
  readonly releaseId: string;
  readonly eifArtifactPath: string;
  readonly runtimeIdentityDigest: Digest64;
  readonly recipientKmsReceiptDigest: Digest64;
  readonly assignmentAcknowledgmentDigest: Digest64;
  readonly routeProofDigest: Digest64;
  readonly admissionProofDigest: Digest64;
  readonly queueChecksDigest: Digest64;
  readonly dlqChecksDigest: Digest64;
  readonly aciReportSignatureDigest: Digest64;
  readonly releaseProvenanceDigest: Digest64;
  readonly finalCommitMarker: Digest64;
}

export interface TrustedEvidenceContextV1 {
  readonly orgId: string;
  readonly deploymentId: string;
  readonly releaseId: string;
  readonly protectedSourceCommit: string;
  readonly eifArtifactPath: string;
  readonly eifDigest: Digest64;
  readonly pcr0: string;
  readonly bootRootDigest: Digest64;
  readonly policyDigest: Digest64;
  readonly policyGeneration: number;
  readonly activationGeneration: number;
  readonly keysetHighWaterEpoch: number;
  readonly keysetHighWaterDigest: Digest64;
  readonly bootEpoch: number;
  readonly sessionId: string;
  readonly releaseProvenanceDigest: Digest64;
  readonly finalCommitMarker: Digest64;
  readonly values: TypedGatewayEvidenceValuesV1;
}

export type TrustedEvidenceContextErrorCode =
  | 'trusted_evidence_context_unavailable'
  | 'trusted_evidence_context_invalid';

export class TrustedEvidenceContextError extends Error {
  readonly code: TrustedEvidenceContextErrorCode;

  constructor(code: TrustedEvidenceContextErrorCode) {
    super(code);
    this.name = 'TrustedEvidenceContextError';
    this.code = code;
  }
}

const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const EIF_ARTIFACT_PATH_PATTERN =
  /^artifacts\/[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*\.eif$/;

// The only evidence-context authority: built from verified boot state at composition time
// and read-only afterwards. There is no setter and no caller-supplied override; a recorder
// constructed with this provider can only record evidence bound to the verified enclave state.
export class TrustedEvidenceContextProvider {
  readonly #verifiedBootManifest: VerifiedBootManifest;
  readonly #activePolicySnapshot: VerifiedActivePolicySnapshotV1;
  readonly #acceptedFloorSnapshot: TrustedFloorSnapshotV1;
  readonly #sessionState: TrustedEvidenceSessionStateV1;
  readonly #releaseState: TrustedReleaseStateV1;

  constructor(deps: {
    verifiedBootManifest: VerifiedBootManifest;
    activePolicySnapshot: VerifiedActivePolicySnapshotV1;
    acceptedFloorSnapshot: TrustedFloorSnapshotV1;
    sessionState: TrustedEvidenceSessionStateV1;
    releaseState: TrustedReleaseStateV1;
  }) {
    if (
      !deps ||
      !deps.verifiedBootManifest ||
      !deps.activePolicySnapshot ||
      !deps.acceptedFloorSnapshot ||
      !deps.sessionState ||
      !deps.releaseState
    ) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_unavailable');
    }
    this.#verifiedBootManifest = deps.verifiedBootManifest;
    this.#activePolicySnapshot = deps.activePolicySnapshot;
    this.#acceptedFloorSnapshot = deps.acceptedFloorSnapshot;
    this.#sessionState = deps.sessionState;
    this.#releaseState = deps.releaseState;
  }

  current(): TrustedEvidenceContextV1 {
    const manifest = this.#verifiedBootManifest;
    const snapshot = this.#activePolicySnapshot;
    const generationContext = snapshot.generationContext;
    const floor = this.#acceptedFloorSnapshot;
    const release = this.#releaseState;
    const session = this.#sessionState;

    if (
      manifest.orgId !== snapshot.orgId ||
      snapshot.orgId !== generationContext.orgId ||
      manifest.deploymentId !== snapshot.deploymentId ||
      snapshot.deploymentId !== generationContext.deploymentId
    ) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
    if (release.releaseId !== generationContext.releaseId) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
    if (floor.checkpointDigest !== snapshot.durableCheckpoint.checkpointDigest) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
    if (
      !IDENTIFIER_PATTERN.test(session.sessionId) ||
      !Number.isSafeInteger(session.bootEpoch) ||
      session.bootEpoch < 1
    ) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
    if (!EIF_ARTIFACT_PATH_PATTERN.test(release.eifArtifactPath)) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
    const releaseDigests: ReadonlyArray<readonly [string, string]> = [
      ['runtimeIdentityDigest', release.runtimeIdentityDigest],
      ['recipientKmsReceiptDigest', release.recipientKmsReceiptDigest],
      ['assignmentAcknowledgmentDigest', release.assignmentAcknowledgmentDigest],
      ['routeProofDigest', release.routeProofDigest],
      ['admissionProofDigest', release.admissionProofDigest],
      ['queueChecksDigest', release.queueChecksDigest],
      ['dlqChecksDigest', release.dlqChecksDigest],
      ['aciReportSignatureDigest', release.aciReportSignatureDigest],
      ['releaseProvenanceDigest', release.releaseProvenanceDigest],
      ['finalCommitMarker', release.finalCommitMarker],
    ];
    for (const [, value] of releaseDigests) {
      if (!DIGEST_PATTERN.test(value)) {
        throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
      }
    }

    const values = this.buildValues(snapshot, generationContext, release);
    const parsedValues = typedGatewayEvidenceValuesSchema.safeParse(values);
    if (!parsedValues.success) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
    return Object.freeze({
      orgId: manifest.orgId,
      deploymentId: manifest.deploymentId,
      releaseId: generationContext.releaseId,
      protectedSourceCommit: generationContext.protectedSourceCommit,
      eifArtifactPath: release.eifArtifactPath,
      eifDigest: generationContext.eifDigest,
      pcr0: generationContext.pcr0,
      bootRootDigest: generationContext.bootRootDigest,
      policyDigest: snapshot.policyDigest,
      policyGeneration: snapshot.policyGeneration,
      activationGeneration: snapshot.activationGeneration,
      keysetHighWaterEpoch: floor.keysetHighWater.epoch,
      keysetHighWaterDigest: floor.keysetHighWater.digest,
      bootEpoch: session.bootEpoch,
      sessionId: session.sessionId,
      releaseProvenanceDigest: release.releaseProvenanceDigest,
      finalCommitMarker: release.finalCommitMarker,
      values: parsedValues.data,
    });
  }

  assertSnapshot(snapshot: VerifiedActivePolicySnapshotV1): void {
    if (snapshot !== this.#activePolicySnapshot) {
      throw new TrustedEvidenceContextError('trusted_evidence_context_invalid');
    }
  }

  private buildValues(
    snapshot: VerifiedActivePolicySnapshotV1,
    generationContext: VerifiedActivePolicySnapshotV1['generationContext'],
    release: TrustedReleaseStateV1,
  ): Record<string, EvidenceValueV1> {
    return {
      policyDigest: this.digestValue(snapshot.policyDigest),
      policyGeneration: this.countValue(snapshot.policyGeneration),
      activationGeneration: this.countValue(snapshot.activationGeneration),
      configurationGeneration: this.countValue(snapshot.configurationGeneration),
      keysetEpoch: this.countValue(generationContext.keysetEpoch),
      keysetDigest: this.digestValue(generationContext.keysetDigest),
      runtimeIdentityDigest: this.digestValue(release.runtimeIdentityDigest),
      recipientKmsReceiptDigest: this.digestValue(release.recipientKmsReceiptDigest),
      assignmentAcknowledgmentDigest: this.digestValue(release.assignmentAcknowledgmentDigest),
      routeProofDigest: this.digestValue(release.routeProofDigest),
      admissionProofDigest: this.digestValue(release.admissionProofDigest),
      queueChecksDigest: this.digestValue(release.queueChecksDigest),
      dlqChecksDigest: this.digestValue(release.dlqChecksDigest),
      aciReportSignatureDigest: this.digestValue(release.aciReportSignatureDigest),
      releaseProvenanceDigest: this.digestValue(release.releaseProvenanceDigest),
      finalCommitMarker: this.digestValue(release.finalCommitMarker),
    };
  }

  private digestValue(value: string): EvidenceValueV1 {
    return { kind: 'digest', value };
  }

  private countValue(value: number): EvidenceValueV1 {
    return { kind: 'boundedCount', value };
  }
}

export function trustedEvidenceContextDigestV1(context: TrustedEvidenceContextV1): Digest64 {
  return sha256Hex(canonicalJson(context));
}
