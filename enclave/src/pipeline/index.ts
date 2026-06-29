// Pipeline entry point — normalise → embed → score → write graph.
// Populated incrementally as enclave pipeline is built out.
export async function handle(_plaintext: Buffer, _masterKey: Buffer): Promise<void> {
  // TODO: wire normalise → embed (Tinfoil) → score → FalkorDB
}
