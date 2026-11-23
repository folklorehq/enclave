import {
  SIGNED_CONNECTOR_FEED_MAX_ENTRIES,
  firstpartyConnectorFeedSchema,
} from '@folklore/contracts/enclave';
import { FirstpartyFeedError } from '@folklore/errors';
import { ResponseBodyTooLargeError, readBoundedText } from '../inference/bounded-response-body.js';
import { assertControlPlaneOrigin } from '../pull/control-plane-url.js';
import {
  FirstpartyDefinitionVerifier,
  type FirstpartyFeedEntry,
  type VerifiedFirstpartyFeed,
} from './FirstpartyDefinitionVerifier.js';

export const FIRSTPARTY_FEED_MAX_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const entrySchema = firstpartyConnectorFeedSchema.shape.definitions.element;

interface FeedCandidates {
  readonly entries: readonly FirstpartyFeedEntry[];
  readonly malformed: number;
}

export class HttpFirstpartyDefinitionFeed {
  constructor(
    private readonly deps: {
      readonly controlPlaneUrl: string;
      readonly deploymentId: string;
      readonly agentToken: () => string;
      readonly fetchImpl: typeof globalThis.fetch;
      readonly verifier: FirstpartyDefinitionVerifier;
    },
  ) {
    assertControlPlaneOrigin(deps.controlPlaneUrl);
  }

  async load(): Promise<VerifiedFirstpartyFeed> {
    this.deps.verifier.assertPinned();
    const text = await this.fetchText();
    const { entries, malformed } = this.candidatesOf(text);
    return this.deps.verifier.verify(entries, malformed);
  }

  // Every failure here is a fixed code: a transport error can quote the URL, a body can quote the feed.
  private async fetchText(): Promise<string> {
    const token = this.deps.agentToken();
    if (!token) throw new FirstpartyFeedError('firstparty_feed_unavailable');
    let response: Response;
    try {
      response = await this.deps.fetchImpl(this.feedUrl(), {
        method: 'GET',
        headers: { authorization: `Bearer ${token}` },
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new FirstpartyFeedError('firstparty_feed_unavailable');
    }
    if (!response.ok || response.body === null) {
      throw new FirstpartyFeedError('firstparty_feed_unavailable');
    }
    try {
      return await readBoundedText(response, FIRSTPARTY_FEED_MAX_BYTES);
    } catch (error) {
      throw new FirstpartyFeedError(
        error instanceof ResponseBodyTooLargeError
          ? 'firstparty_feed_too_large'
          : 'firstparty_feed_unavailable',
      );
    }
  }

  private feedUrl(): string {
    const deployment = encodeURIComponent(this.deps.deploymentId);
    return `${this.deps.controlPlaneUrl}/v1/deployments/${deployment}/firstparty-connectors`;
  }

  private candidatesOf(text: string): FeedCandidates {
    const raw = this.rawEntries(text);
    if (raw.length > SIGNED_CONNECTOR_FEED_MAX_ENTRIES) {
      throw new FirstpartyFeedError('firstparty_feed_too_many');
    }
    FirstpartyDefinitionVerifier.assertUniqueKeys(raw.flatMap((entry) => this.rawNameOf(entry)));
    const entries: FirstpartyFeedEntry[] = [];
    for (const candidate of raw) {
      const parsed = entrySchema.safeParse(candidate);
      if (parsed.success) entries.push(parsed.data);
    }
    return { entries, malformed: raw.length - entries.length };
  }

  private rawEntries(text: string): readonly unknown[] {
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new FirstpartyFeedError('firstparty_feed_invalid');
    }
    const definitions = (body as { definitions?: unknown } | null)?.definitions;
    if (typeof body !== 'object' || body === null || !Array.isArray(definitions)) {
      throw new FirstpartyFeedError('firstparty_feed_invalid');
    }
    return definitions;
  }

  private rawNameOf(entry: unknown): string[] {
    const envelope = (entry as { envelope?: { slot?: unknown; kind?: unknown } } | null)?.envelope;
    const name = envelope?.slot ?? envelope?.kind;
    return typeof name === 'string' ? [name] : [];
  }
}
