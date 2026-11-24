import {
  builtinSpecKinds,
  checkBuiltinConnectorDefinition,
  useVerifiedSpecs,
} from '@folklore/connectors';
import type { ConnectorSpec } from '@folklore/contracts';
import type { Logger } from '@folklore/core';
import { FirstpartyFeedError } from '@folklore/errors';
import { HttpFirstpartyDefinitionFeed } from './HttpFirstpartyDefinitionFeed.js';
import {
  FirstpartyDefinitionVerifier,
  type VerifiedFirstpartyFeed,
} from './FirstpartyDefinitionVerifier.js';

const SIGNED_SPEC_REFRESH_MS = 300_000;

const REFRESH_FAILED = 'firstparty_feed_unavailable';
const REVISION_ROLLBACK = 'builtin_revision_rollback';

interface InstalledSpec {
  readonly revision: number;
  readonly spec: ConnectorSpec;
}

interface SignedSpecLoaderDeps {
  readonly feed: { load(): Promise<VerifiedFirstpartyFeed> };
  readonly logger: Logger;
}

// Hands a built-in connector kind's signed spec to the registry once it passes the same check the
// control plane ran. A kind that is absent, refused or unreadable keeps its compiled-in spec.
class SignedSpecLoader {
  private installed: ReadonlyMap<string, InstalledSpec> = new Map();
  private inFlight: Promise<void> | undefined;
  private timer: NodeJS.Timeout | undefined;

  constructor(private readonly deps: SignedSpecLoaderDeps) {}

  refreshOnce(): Promise<void> {
    this.inFlight ??= this.refresh().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  start(): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => void this.refreshOnce(), SIGNED_SPEC_REFRESH_MS);
    this.timer.unref();
  }

  private async refresh(): Promise<void> {
    let feed: VerifiedFirstpartyFeed;
    try {
      feed = await this.deps.feed.load();
    } catch (error) {
      const errorCode = error instanceof FirstpartyFeedError ? error.code : REFRESH_FAILED;
      this.deps.logger.warn('signed_specs_refresh_failed', { errorCode });
      return;
    }
    const next = new Map<string, InstalledSpec>();
    let refused = 0;
    for (const entry of feed.values()) {
      if (entry.form !== 'builtin') continue;
      const kept = this.installed.get(entry.key);
      if (kept && kept.revision > entry.revision) {
        next.set(entry.key, kept);
        refused += 1;
        this.logRefusal(REVISION_ROLLBACK, entry.key);
        continue;
      }
      const checked = checkBuiltinConnectorDefinition(entry.key, entry.definition);
      if (checked.ok) {
        next.set(entry.key, { revision: entry.revision, spec: checked.spec });
        continue;
      }
      refused += 1;
      for (const code of new Set(checked.issues.map((issue) => issue.code))) {
        this.logRefusal(code, entry.key);
      }
    }
    this.apply(next);
    this.deps.logger.info('signed_specs_loaded', { count: next.size, refused });
  }

  private apply(next: ReadonlyMap<string, InstalledSpec>): void {
    useVerifiedSpecs(new Map([...next].map(([kind, installed]) => [kind, installed.spec])));
    this.installed = next;
  }

  // The code is a fixed slug; a kind with no compiled-in spec is a signer's own string, so it is left out.
  private logRefusal(errorCode: string, kind: string): void {
    const known = builtinSpecKinds().includes(kind);
    this.deps.logger.warn(
      'signed_spec_refused',
      known ? { errorCode, component: kind } : { errorCode },
    );
  }
}

interface SignedSpecLoaderConfig {
  readonly signerPublicKeySpki: string | null;
  readonly controlPlaneUrl: string;
  readonly deploymentId: string;
  readonly agentToken: () => string;
  readonly fetchImpl: typeof globalThis.fetch;
  readonly logger: Logger;
}

// With no pinned signer key in the signed boot manifest there is nothing to verify against, so no loader exists.
export function createSignedSpecLoader(config: SignedSpecLoaderConfig): SignedSpecLoader | null {
  if (config.signerPublicKeySpki === null) return null;
  const verifier = new FirstpartyDefinitionVerifier({
    signerPublicKeySpki: config.signerPublicKeySpki,
    logger: config.logger,
  });
  const feed = new HttpFirstpartyDefinitionFeed({
    controlPlaneUrl: config.controlPlaneUrl,
    deploymentId: config.deploymentId,
    agentToken: config.agentToken,
    fetchImpl: config.fetchImpl,
    verifier,
  });
  return new SignedSpecLoader({ feed, logger: config.logger });
}
