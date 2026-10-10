export type BootSessionState = Readonly<{ sessionId: string; bootEpoch: number }>;

export interface RuntimeEvidenceSessionPort {
  /** Throws unless the boot manifest is verified and the boot has recorded its KMS unseal. */
  runtimeEvidenceSession(): BootSessionState;
}
