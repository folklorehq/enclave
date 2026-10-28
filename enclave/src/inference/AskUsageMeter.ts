import type { TokenUsage } from '@folklore/contracts/enclave';
import type { AskUsageSinkPort } from '@folklore/api';
import { contentFreeErrorType, type Logger } from '@folklore/core';
import { tokenUsageScope, type MeasuredRun } from './TokenUsageScope.js';

// Same bound the Ask stream service gives a dropped stream to settle; past it the usage seen so far is recorded.
export const ABANDONED_STREAM_SETTLE_MS = 2_000;

interface SettlingStream extends AsyncIterable<string> {
  readonly settled?: Promise<void>;
}

export interface AskUsageMeterDeps {
  readonly sink: AskUsageSinkPort;
  readonly logger: Logger;
  readonly now?: () => Date;
}

interface OpenedStream {
  readonly source: Promise<AsyncIterable<string>>;
  readonly peek: () => TokenUsage[];
}

/** Records the token counts of an answer or agent run into the org's day usage; a sink fault never fails the run. */
export class AskUsageMeter {
  constructor(private readonly deps: AskUsageMeterDeps) {}

  async generate(orgId: string, run: () => Promise<string>): Promise<string> {
    let partial: TokenUsage[] = [];
    let measured: MeasuredRun<string>;
    try {
      measured = await tokenUsageScope.measure(run, (usage) => {
        partial = usage;
      });
    } catch (error) {
      await this.record(orgId, partial);
      throw error;
    }
    await this.record(orgId, measured.usage);
    return measured.result;
  }

  // The provider call's usage events fire in the async context where `open` runs, so the scope must be open there, not per read.
  stream(orgId: string, open: () => AsyncIterable<string>): AsyncIterable<string> {
    const opened = this.openMetered(open);
    return this.relay(orgId, opened);
  }

  private openMetered(open: () => AsyncIterable<string>): OpenedStream {
    let peek: () => TokenUsage[] = () => [];
    const source = tokenUsageScope
      .measure(
        async () => open(),
        undefined,
        undefined,
        (peeker) => {
          peek = peeker;
        },
      )
      .then((measured) => measured.result);
    source.catch(() => undefined);
    return { source, peek: () => peek() };
  }

  private async *relay(orgId: string, opened: OpenedStream): AsyncGenerator<string> {
    let source: SettlingStream | undefined;
    try {
      source = await opened.source;
      yield* source;
    } finally {
      await this.awaitSettled(source);
      await this.record(orgId, opened.peek());
    }
  }

  // An aborted provider stream reports its usage only after the abort reaches it, which is after the consumer has already returned.
  private async awaitSettled(source: SettlingStream | undefined): Promise<void> {
    if (source?.settled === undefined) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const grace = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, ABANDONED_STREAM_SETTLE_MS);
    });
    try {
      await Promise.race([source.settled, grace]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async record(orgId: string, usage: readonly TokenUsage[]): Promise<void> {
    if (usage.length === 0) return;
    try {
      await this.deps.sink.record(orgId, (this.deps.now ?? (() => new Date()))(), usage);
    } catch (error) {
      this.deps.logger.warn('ask_usage_record_failed', {
        orgId,
        error_type: contentFreeErrorType(error),
      });
    }
  }
}
