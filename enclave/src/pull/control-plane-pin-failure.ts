export const CONTROL_PLANE_SPKI_PIN_MISMATCH = 'control_plane_spki_pin_mismatch';

const MAX_CAUSE_DEPTH = 8;

export function isControlPlanePinMismatch(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH; depth += 1) {
    if (!(current instanceof Error)) return false;
    if (current.message === CONTROL_PLANE_SPKI_PIN_MISMATCH) return true;
    current = current.cause;
  }
  return false;
}
