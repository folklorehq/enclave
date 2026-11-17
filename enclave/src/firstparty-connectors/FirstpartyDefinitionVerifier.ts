import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import {
  firstpartyDefinitionSha256,
  firstpartyDefinitionSigningBytes,
  isFirstpartySourceKey,
  type FirstpartyDefinition,
  type FirstpartySourceKey,
} from '@folklore/contracts';
import type { FirstpartyConnectorFeed } from '@folklore/contracts/enclave';
import type { Logger } from '@folklore/core';
import { FirstpartyFeedError, type FirstpartyFeedErrorCode } from '@folklore/errors';

export type FirstpartyFeedEntry = FirstpartyConnectorFeed['definitions'][number];

export interface VerifiedFirstpartyDefinition {
  readonly key: FirstpartySourceKey;
  readonly definitionId: string;
  readonly revision: number;
  readonly definition: FirstpartyDefinition;
  readonly definitionSha256: string;
  readonly signatureB64: string;
  readonly oauthClientSecretCiphertextB64: string | null;
}
export type VerifiedFirstpartyFeed = ReadonlyMap<FirstpartySourceKey, VerifiedFirstpartyDefinition>;

type EntryRefusal = Extract<
  FirstpartyFeedErrorCode,
  'firstparty_feed_slot_mismatch' | 'firstparty_feed_signature_invalid'
>;

// UNWIRED: no composition root builds this yet.
export class FirstpartyDefinitionVerifier {
  private readonly publicKey: KeyObject | null;

  constructor(
    private readonly deps: { readonly signerPublicKeySpki: string | null; readonly logger: Logger },
  ) {
    this.publicKey = FirstpartyDefinitionVerifier.parsePin(deps.signerPublicKeySpki);
  }

  static assertUniqueKeys(keys: readonly string[]): void {
    if (new Set(keys).size !== keys.length) {
      throw new FirstpartyFeedError('firstparty_feed_duplicate_key');
    }
  }

  private static parsePin(spki: string | null): KeyObject | null {
    if (spki === null) return null;
    try {
      const key = createPublicKey({
        key: Buffer.from(spki, 'base64'),
        format: 'der',
        type: 'spki',
      });
      return key.asymmetricKeyType === 'ed25519' ? key : null;
    } catch {
      return null;
    }
  }

  assertPinned(): KeyObject {
    if (this.publicKey === null) throw new FirstpartyFeedError('firstparty_feed_pin_missing');
    return this.publicKey;
  }

  verify(entries: readonly FirstpartyFeedEntry[], malformed: number): VerifiedFirstpartyFeed {
    const publicKey = this.assertPinned();
    FirstpartyDefinitionVerifier.assertUniqueKeys(entries.map((entry) => entry.envelope.slot));
    const verified = new Map<FirstpartySourceKey, VerifiedFirstpartyDefinition>();
    let dropped = 0;
    for (const entry of entries) {
      const refusal = this.refusalOf(entry, publicKey);
      if (refusal === null) {
        const accepted = this.accept(entry);
        verified.set(accepted.key, accepted);
        continue;
      }
      dropped += 1;
      this.logRefusal(refusal, entry.envelope.slot);
    }
    this.deps.logger.info('firstparty_feed_verified', {
      count: verified.size,
      dropped,
      failed: malformed,
    });
    return verified;
  }

  private refusalOf(entry: FirstpartyFeedEntry, publicKey: KeyObject): EntryRefusal | null {
    const { slot, definition } = entry.envelope;
    // Checked before the signing bytes are built, because they throw on a mismatch.
    if (!isFirstpartySourceKey(slot) || slot !== definition.slot || slot !== definition.spec.kind) {
      return 'firstparty_feed_slot_mismatch';
    }
    const signature = Buffer.from(entry.signatureB64, 'base64');
    return verify(null, firstpartyDefinitionSigningBytes(entry.envelope), publicKey, signature)
      ? null
      : 'firstparty_feed_signature_invalid';
  }

  private accept(entry: FirstpartyFeedEntry): VerifiedFirstpartyDefinition {
    const { slot, definitionId, revision, definition } = entry.envelope;
    return {
      key: slot as FirstpartySourceKey,
      definitionId,
      revision,
      definition,
      definitionSha256: firstpartyDefinitionSha256(definition),
      signatureB64: entry.signatureB64,
      oauthClientSecretCiphertextB64: entry.oauthClientSecretCiphertextB64,
    };
  }

  // The key is a fleet-wide literal, never customer content; an unparsable slot is left out.
  private logRefusal(errorCode: EntryRefusal, slot: string): void {
    this.deps.logger.warn(
      'firstparty_definition_refused',
      isFirstpartySourceKey(slot) ? { errorCode, component: slot } : { errorCode },
    );
  }
}
