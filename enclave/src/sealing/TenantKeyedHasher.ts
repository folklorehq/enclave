import { createHmac, type Hmac } from 'node:crypto';

const HMAC_ALGORITHM = 'sha256';

// Holds one tenant-derived HMAC key; callers own their domain strings.
export class TenantKeyedHasher {
  private key: Buffer | null;

  constructor(
    key: Buffer,
    private readonly zeroizedError: () => Error,
  ) {
    this.key = key;
  }

  begin(domain: string): Hmac {
    return createHmac(HMAC_ALGORITHM, this.liveKey()).update(domain);
  }

  zeroize(): void {
    this.key?.fill(0);
    this.key = null;
  }

  // A zeroed key is publicly known, so a hasher past zeroize must refuse rather than HMAC under it.
  private liveKey(): Buffer {
    if (this.key === null) throw this.zeroizedError();
    return this.key;
  }
}
