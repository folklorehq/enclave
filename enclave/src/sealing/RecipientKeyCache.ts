import type { Logger } from '@folklore/core';
import type { KeyObject } from 'crypto';

export interface RecipientKeyPair {
  publicKeyDer: Buffer;
  privateKey: KeyObject;
}

export interface RecipientKeySource {
  acquire(): Promise<RecipientKeyPair>;
}

export interface RecipientKeyCacheOptions {
  generate: () => Promise<RecipientKeyPair>;
  ttlMs: number;
  refreshLeadMs: number;
  logger: Logger;
  now?: () => number;
}

interface CachedKeyPair {
  value: RecipientKeyPair;
  refreshAt: number;
  expiresAt: number;
}

// Only the key pair is cached: every KMS request still carries a freshly attested document.
// The pair lives in this process's memory only; a rotation drops the last reference to the old private key.
export class RecipientKeyCache implements RecipientKeySource {
  private current: CachedKeyPair | undefined;
  private inflight: Promise<CachedKeyPair> | undefined;
  private readonly now: () => number;

  constructor(private readonly options: RecipientKeyCacheOptions) {
    this.now = options.now ?? (() => performance.now());
  }

  async acquire(): Promise<RecipientKeyPair> {
    const entry = this.current;
    if (entry !== undefined && this.now() < entry.expiresAt) {
      if (this.now() >= entry.refreshAt) this.refreshInBackground();
      return entry.value;
    }
    return (await this.generation()).value;
  }

  private refreshInBackground(): void {
    // UNWIRED reader: enclave logs have no reader in production, so a failed refresh is visible only in debug runs until it rides the check-in relay.
    void this.generation().catch(() => this.options.logger.warn('recipient_refresh_failed'));
  }

  private generation(): Promise<CachedKeyPair> {
    if (this.inflight !== undefined) return this.inflight;
    const pending = this.mint().finally(() => {
      this.inflight = undefined;
    });
    this.inflight = pending;
    return pending;
  }

  private async mint(): Promise<CachedKeyPair> {
    const value = await this.options.generate();
    const mintedAt = this.now();
    const entry = {
      value,
      refreshAt: mintedAt + this.options.ttlMs - this.options.refreshLeadMs,
      expiresAt: mintedAt + this.options.ttlMs,
    };
    this.current = entry;
    return entry;
  }
}
