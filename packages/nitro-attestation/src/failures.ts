export const nitroAttestationFailureCodes = [
  'malformed_document',
  'invalid_cose_profile',
  'invalid_certificate_path',
  'invalid_document_signature',
  'invalid_document_fields',
  'runtime_binding_mismatch',
] as const;

export type NitroAttestationFailureCode = (typeof nitroAttestationFailureCodes)[number];

export class NitroAttestationError extends Error {
  readonly code: NitroAttestationFailureCode;

  constructor(code: NitroAttestationFailureCode) {
    super(code);
    this.name = 'NitroAttestationError';
    this.code = code;
  }
}
