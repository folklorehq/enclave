import type {
  AciTrustContext,
  InferenceBackend,
  VerifiedActivePolicySnapshotV1,
} from '@folklore/inference';

export interface OfficialAciProductionCompositionPort {
  readonly backend: InferenceBackend;
  readonly activePolicySnapshot: VerifiedActivePolicySnapshotV1;
  readonly trustContext: AciTrustContext;
}
