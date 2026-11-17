import type { TransportResponse } from '@folklore/core';
import { ConnectorSpecError } from '@folklore/errors';

export class BufferedTransportResponse implements TransportResponse {
  constructor(
    readonly status: number,
    private readonly headers: Headers,
    private readonly text: string,
  ) {}

  header(name: string): string | null {
    return this.headers.get(name);
  }

  async json(): Promise<unknown> {
    try {
      return JSON.parse(this.text) as unknown;
    } catch {
      throw new ConnectorSpecError('spec_response_not_json');
    }
  }
}
