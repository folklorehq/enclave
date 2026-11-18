export const VERIFIER_UNAVAILABLE_CODE = 'help_center_verifier_unavailable';

export class HelpCenterVerifierUnavailableError extends Error {
  constructor() {
    super(VERIFIER_UNAVAILABLE_CODE);
    this.name = 'HelpCenterVerifierUnavailableError';
  }
}
