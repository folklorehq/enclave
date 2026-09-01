// The only error detail allowed out of a catch that has decrypted content in scope.
// `errorName` is safe by construction — every reachable name is a class name. `errorCode` is not:
// a library is free to put anything in `code`, so it must look like an identifier (ENOENT,
// ThrottlingException, ERR_TLS_CERT_ALTNAME_INVALID) rather than merely be short. That narrows
// content to strings with no space or punctuation; it does not eliminate it.
const CODE_SHAPE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
export function errorName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err;
}

export function errorCode(err: unknown): string | undefined {
  if (typeof err !== 'object' || err === null || !('code' in err)) return undefined;
  const code = (err as { code: unknown }).code;
  if (typeof code !== 'string' || !CODE_SHAPE.test(code)) return undefined;
  return code;
}

export function errorType(err: unknown): string {
  try {
    if (err instanceof AggregateError) return 'aggregate_error';
    if (err instanceof EvalError) return 'eval_error';
    if (err instanceof RangeError) return 'range_error';
    if (err instanceof ReferenceError) return 'reference_error';
    if (err instanceof SyntaxError) return 'syntax_error';
    if (err instanceof TypeError) return 'type_error';
    if (err instanceof URIError) return 'uri_error';
    if (err instanceof Error) return 'error';
    switch (typeof err) {
      case 'bigint':
        return 'bigint_error';
      case 'boolean':
        return 'boolean_error';
      case 'function':
        return 'function_error';
      case 'number':
        return 'number_error';
      case 'object':
        return 'object_error';
      case 'string':
        return 'string_error';
      case 'symbol':
        return 'symbol_error';
      case 'undefined':
        return 'undefined_error';
    }
  } catch {
    return 'unknown_error';
  }
}
