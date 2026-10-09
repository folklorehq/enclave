/** The boot steps a pre-ready failure is named by (`<step>_failed[_<class>]`), in boot order. */
export const ENCLAVE_BOOT_STEPS = [
  'boot_compose',
  'attestation_prepare',
  'boot_policy_load',
  'boot_assignments_apply',
  'inference_key_read',
  'inference_configure',
  'agent_token_load',
  'output_signer_load',
  'oauth_ingress_setup',
  'halt_gate_setup',
  'assignments_load',
  'ops_telemetry_setup',
  'api_start',
  'attestation_listener_start',
  'workers_start',
] as const;

export type EnclaveBootStep = (typeof ENCLAVE_BOOT_STEPS)[number];
