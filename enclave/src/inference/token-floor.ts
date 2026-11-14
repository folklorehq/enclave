export const CHARS_PER_TOKEN_FLOOR = 3;

export function promptTokenFloor(chars: number): number {
  return Math.ceil(chars / CHARS_PER_TOKEN_FLOOR);
}
