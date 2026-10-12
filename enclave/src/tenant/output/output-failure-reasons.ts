export const OUTPUT_PAYLOAD_NOT_JSON = 'output_payload_not_json';

export const EMIT_STEP_REASONS = {
  validate: 'output_validate_failed',
  bind: 'output_bind_failed',
  sign: 'output_sign_failed',
  serialize: 'output_serialize_failed',
  send: 'output_send_failed',
} as const;

export type EmitStep = keyof typeof EMIT_STEP_REASONS;

export const OUTPUT_FAILURE_REASONS = [
  OUTPUT_PAYLOAD_NOT_JSON,
  ...Object.values(EMIT_STEP_REASONS),
] as const;
