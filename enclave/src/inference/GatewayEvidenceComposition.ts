import type { EvidenceAnchorVerifier } from './EvidenceAnchorVerifier.js';
import type { EvidenceKeySession } from './EvidenceKeySession.js';
import { GatewayEvidenceRecorder } from './GatewayEvidenceRecorder.js';
import type { TrustedEvidenceContextProvider } from './TrustedEvidenceContextProvider.js';
import type { VerifiedActivePolicySnapshotV1 } from '@folklore/inference';

export type GatewayEvidenceCompositionErrorCode = 'evidence_composition_incomplete';

export class GatewayEvidenceCompositionError extends Error {
  readonly code: GatewayEvidenceCompositionErrorCode;

  constructor(code: GatewayEvidenceCompositionErrorCode) {
    super(code);
    this.name = 'GatewayEvidenceCompositionError';
    this.code = code;
  }
}

export interface GatewayEvidenceCompositionDeps {
  provider: TrustedEvidenceContextProvider;
  anchorVerifier: EvidenceAnchorVerifier;
  keySession: EvidenceKeySession;
}

// The only constructor helper for the evidence recorder: a production recorder cannot be
// built without trusted context, an anchor verifier, and a typed evidence session. The runtime
// composition exposes this helper only after prepare() has produced a verified boot manifest.
export class GatewayEvidenceComposition {
  readonly #provider: TrustedEvidenceContextProvider;
  readonly #anchorVerifier: EvidenceAnchorVerifier;
  readonly #keySession: EvidenceKeySession;

  constructor(deps: GatewayEvidenceCompositionDeps) {
    if (!deps || !deps.provider || !deps.anchorVerifier || !deps.keySession) {
      throw new GatewayEvidenceCompositionError('evidence_composition_incomplete');
    }
    this.#provider = deps.provider;
    this.#anchorVerifier = deps.anchorVerifier;
    this.#keySession = deps.keySession;
  }

  createRecorder(): GatewayEvidenceRecorder {
    return new GatewayEvidenceRecorder(this.#provider, this.#anchorVerifier, this.#keySession);
  }

  assertSnapshot(snapshot: VerifiedActivePolicySnapshotV1): void {
    this.#provider.assertSnapshot(snapshot);
  }
}
