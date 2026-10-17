// A leaf: the refresh path, the trusted-time authority and the turnstile would otherwise import each other.
export const DEFAULT_REFRESH_TIMEOUT_MS = 5_000;
export const ATTESTATION_TURN_ABANDONED = 'nsm_attestation_turn_abandoned';

export class AttestationTurnAbandoned extends Error {
  constructor(cause?: unknown) {
    super(ATTESTATION_TURN_ABANDONED, cause === undefined ? undefined : { cause });
    this.name = 'AttestationTurnAbandoned';
  }
}
