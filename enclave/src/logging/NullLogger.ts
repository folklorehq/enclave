import type { Logger } from '@folklore/core';

export class NullLogger implements Logger {
  trace(): void {}
  debug(): void {}
  info(): void {}
  warn(): void {}
  error(): void {}
  fatal(): void {}
  child(): Logger {
    return this;
  }
}
