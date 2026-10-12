export const OUTPUT_PAYLOAD_NOT_JSON = 'output_payload_not_json';

/** A copy of `value` with `undefined` object members dropped; refuses anything JSON cannot carry exactly. */
export function jsonOutputPayload(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(OUTPUT_PAYLOAD_NOT_JSON);
    return value;
  }
  // An undefined element or a hole would serialize as null, which is not the same value.
  if (Array.isArray(value)) {
    return Array.from(value, (item: unknown) => {
      if (item === undefined) throw new Error(OUTPUT_PAYLOAD_NOT_JSON);
      return jsonOutputPayload(item);
    });
  }
  if (!isPlainRecord(value)) throw new Error(OUTPUT_PAYLOAD_NOT_JSON);
  const members: Record<string, unknown> = {};
  for (const [key, member] of Object.entries(value)) {
    if (member === undefined) continue;
    // defineProperty, not assignment: an own "__proto__" member must stay data, never a prototype.
    Object.defineProperty(members, key, {
      value: jsonOutputPayload(member),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return members;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
