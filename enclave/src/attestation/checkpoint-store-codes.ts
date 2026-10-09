// Every code KmsSealedAttestationBootCheckpointStore throws; boot-prepare-failure.test.ts holds them equal.
export const ATTESTATION_BOOT_CHECKPOINT_STORE_CODES = [
  'attestation_boot_checkpoint_bootstrap_invalid',
  'attestation_boot_checkpoint_config_invalid',
  'attestation_boot_checkpoint_conflict',
  'attestation_boot_checkpoint_identity_invalid',
  'attestation_boot_checkpoint_list_invalid',
  'attestation_boot_checkpoint_missing',
  'attestation_boot_checkpoint_object_invalid',
  'attestation_boot_checkpoint_payload_invalid',
  'attestation_boot_checkpoint_superseded',
  'attestation_boot_checkpoint_unseal_failed',
  'attestation_boot_checkpoint_write_failed',
] as const;
