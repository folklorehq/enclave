import { EncryptionContextMismatchError } from '../crypto/esdk.js';

export type CodeGraphFailureClass = 'corrupt' | 'unavailable';

export const CODE_GRAPH_TOMBSTONE_UNAVAILABLE = 'code_graph_tombstone_unavailable';
export const CODE_GRAPH_ERASE_UNAVAILABLE = 'code_graph_erase_unavailable';

// A missing data key is deliberately absent: a key-service outage looks identical, and a rebuild would drop retirements.
const ESDK_INTEGRITY_MESSAGES: readonly string[] = [
  'Not a supported message format version',
  'Unsupported algorithm suite',
  'Commitment does not match',
  'Overflow, too much data',
  'context parse error',
  'Context does not contain required public key',
  'Encryption context contains public verification key',
  'Compressed point length is not correct',
  'Incomplete Header',
  'unable to authenticate data',
  'Encrypted body sequence out of order',
  'Malformed sequenceNumber',
  'Final frame length exceeds frame length',
  'Incomplete message',
  'Invalid Signature',
];

export class CodeGraphStoreUnavailableError extends Error {
  constructor(code: string) {
    super(code);
    this.name = 'CodeGraphStoreUnavailableError';
  }
}

export class CodeGraphObjectCorruptError extends Error {
  constructor() {
    super('code_graph_object_corrupt');
    this.name = 'CodeGraphObjectCorruptError';
  }
}

export function classifyCodeGraphFailure(error: unknown): CodeGraphFailureClass {
  if (error instanceof EncryptionContextMismatchError) return 'corrupt';
  if (error instanceof CodeGraphObjectCorruptError) return 'corrupt';
  if (!(error instanceof Error) || isServiceFailure(error)) return 'unavailable';
  return ESDK_INTEGRITY_MESSAGES.some((message) => error.message.includes(message))
    ? 'corrupt'
    : 'unavailable';
}

function isServiceFailure(error: Error): boolean {
  return '$metadata' in error || '$fault' in error || error.name.endsWith('Exception');
}
