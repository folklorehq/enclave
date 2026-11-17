import { contentFreeLogCode, type Logger, type SafeLogContext } from '@folklore/core';

export interface ConnectorRuntimeLogFields {
  readonly component: string;
  readonly operation: string;
  readonly httpStatus?: number;
  readonly attempt: number;
  readonly durationMs: 0 | 1000 | 5000 | 30000;
  readonly errorCode?: string;
}

export class ConnectorRuntimeLog {
  constructor(private readonly logger: Logger) {}

  retry(fields: ConnectorRuntimeLogFields): void {
    this.logger.warn('connector_request_retry', this.projection(fields));
  }

  refused(fields: ConnectorRuntimeLogFields): void {
    this.logger.warn('connector_request_refused', this.projection(fields));
  }

  // The logging boundary takes lower-case code tokens only, so names and network codes are normalised and nothing else is carried.
  private projection(fields: ConnectorRuntimeLogFields): SafeLogContext {
    return {
      component: contentFreeLogCode(fields.component),
      operation: contentFreeLogCode(fields.operation),
      attempt: fields.attempt,
      durationMs: fields.durationMs,
      ...(fields.httpStatus === undefined ? {} : { httpStatus: fields.httpStatus }),
      ...(fields.errorCode === undefined
        ? {}
        : { errorCode: contentFreeLogCode(fields.errorCode) }),
    };
  }
}
