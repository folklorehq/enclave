import {
  PULL_FAILURE_ATTEMPTS_MAX,
  PULL_FAILURE_CODE_MAX,
  PULL_FAILURE_CODE_PATTERN,
  type PullFailureReason,
} from '@folklore/contracts/enclave';
import { AppError } from '@folklore/errors';
import { errorType } from '../logging/error-fields.js';
import type { PullNotProcessedReason } from './pull-runner.js';

const NOT_PROCESSED = 'not_processed';
const UNKNOWN_ERROR = 'unknown_error';
const CLIENT_ERROR_MIN = 400;
const SERVER_ERROR_MIN = 500;
const STATUS_MAX = 600;
const CAMEL_BOUNDARY = /([a-z0-9])([A-Z])/g;
// Node system and undici network codes; any other library `code` may carry provider data.
const NETWORK_CODES = [/^E[A-Z]+$/, /^UND_ERR_[A-Z_]+$/];

export interface PullFailure {
  phase: PullFailureReason['phase'];
  error?: unknown;
  code?: PullNotProcessedReason;
}

/** Fixed lower-snake codes describing a failed pull attempt; provider text never enters. */
export function pullFailureReason(failure: PullFailure, attempts: number): PullFailureReason {
  const code = snakeCode(failure.code ?? firstPartyCode(failure.error));
  const operation = snakeCode(connectorOperation(failure.error));
  const statusClass = httpStatusClass(failure.error);
  return {
    phase: failure.phase,
    errorType:
      failure.error === undefined
        ? NOT_PROCESSED
        : (snakeCode(errorType(failure.error)) ?? UNKNOWN_ERROR),
    ...(code ? { errorCode: code } : {}),
    ...(operation ? { operation } : {}),
    ...(statusClass ? { statusClass } : {}),
    attempts: Math.min(attempts, PULL_FAILURE_ATTEMPTS_MAX),
  };
}

function firstPartyCode(error: unknown): string | undefined {
  if (error instanceof AppError) return error.code;
  return networkCode(field(error, 'code')) ?? networkCode(field(field(error, 'cause'), 'code'));
}

function networkCode(code: unknown): string | undefined {
  return typeof code === 'string' && NETWORK_CODES.some((pattern) => pattern.test(code))
    ? code
    : undefined;
}

// Connectors name each provider call with a fixed literal in the error context (BaseConnector.call).
function connectorOperation(error: unknown): string | undefined {
  const operation = field(field(error, 'context'), 'operation');
  return typeof operation === 'string' ? operation : undefined;
}

function snakeCode(value: string | undefined): string | undefined {
  if (value === undefined || value.length > PULL_FAILURE_CODE_MAX) return undefined;
  const snake = value.replace(CAMEL_BOUNDARY, '$1_$2').toLowerCase();
  return snake.length <= PULL_FAILURE_CODE_MAX && PULL_FAILURE_CODE_PATTERN.test(snake)
    ? snake
    : undefined;
}

function httpStatusClass(error: unknown): PullFailureReason['statusClass'] {
  const status = numeric(field(error, 'status')) ?? numeric(field(field(error, 'cause'), 'status'));
  if (status === undefined || status < CLIENT_ERROR_MIN || status >= STATUS_MAX) return undefined;
  return status >= SERVER_ERROR_MIN ? 'server_error' : 'client_error';
}

function field(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null) return undefined;
  try {
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function numeric(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) ? value : undefined;
}
