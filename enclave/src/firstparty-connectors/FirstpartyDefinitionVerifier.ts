import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import {
  builtinDefinitionSha256,
  firstpartyDefinitionSha256,
  isBuiltinEnvelope,
  isFirstpartySourceKey,
  signedConnectorName,
  signedConnectorSigningBytes,
  type BuiltinDefinition,
  type FirstpartyDefinition,
  type FirstpartySourceKey,
  type SignedConnectorEnvelope,
} from '@folklore/contracts';
import { builtinSpecKinds } from '@folklore/connectors';
import type { FirstpartyConnectorFeed } from '@folklore/contracts/enclave';
import type { Logger } from '@folklore/core';
import { FirstpartyFeedError, type FirstpartyFeedErrorCode } from '@folklore/errors';

export type FirstpartyFeedEntry = FirstpartyConnectorFeed['definitions'][number];

interface VerifiedFirstpartyDefinition {
  readonly form: 'slot';
  readonly key: FirstpartySourceKey;
  readonly definitionId: string;
  readonly revision: number;
  readonly definition: FirstpartyDefinition;
  readonly definitionSha256: string;
  readonly signatureB64: string;
  readonly oauthClientSecretCiphertextB64: string | null;
}
interface VerifiedBuiltinDefinition {
  readonly form: 'builtin';
  readonly key: string;
  readonly definitionId: string;
  readonly revision: number;
  readonly definition: BuiltinDefinition;
  readonly definitionSha256: string;
  readonly signatureB64: string;
}
export type VerifiedSignedDefinition = VerifiedFirstpartyDefinition | VerifiedBuiltinDefinition;
// Keyed by connector name: a slot key or a built-in kind.
export type VerifiedFirstpartyFeed = ReadonlyMap<string, VerifiedSignedDefinition>;

type EntryRefusal = Extract<
  FirstpartyFeedErrorCode,
  'firstparty_feed_slot_mismatch' | 'firstparty_feed_signature_invalid'
>;

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
    FirstpartyDefinitionVerifier.assertUniqueKeys(
      entries.map((entry) => signedConnectorName(entry.envelope)),
    );
    const verified = new Map<string, VerifiedSignedDefinition>();
    let dropped = 0;
    for (const entry of entries) {
      const refusal = this.refusalOf(entry, publicKey);
      if (refusal === null) {
        const accepted = this.accept(entry);
        verified.set(accepted.key, accepted);
        continue;
      }
      dropped += 1;
      this.logRefusal(refusal, signedConnectorName(entry.envelope));
    }
    this.deps.logger.info('firstparty_feed_verified', {
      count: verified.size,
      dropped,
      failed: malformed,
    });
    return verified;
  }

  private refusalOf(entry: FirstpartyFeedEntry, publicKey: KeyObject): EntryRefusal | null {
    // Checked before the signing bytes are built, because they throw on a mismatch.
    if (!FirstpartyDefinitionVerifier.namesAgree(entry.envelope)) {
      return 'firstparty_feed_slot_mismatch';
    }
    const signature = Buffer.from(entry.signatureB64, 'base64');
    return verify(null, signedConnectorSigningBytes(entry.envelope), publicKey, signature)
      ? null
      : 'firstparty_feed_signature_invalid';
  }

  private static namesAgree(envelope: SignedConnectorEnvelope): boolean {
    if (isBuiltinEnvelope(envelope)) return envelope.kind === envelope.definition.kind;
    const { slot, definition } = envelope;
    return isFirstpartySourceKey(slot) && slot === definition.slot && slot === definition.spec.kind;
  }

  private accept(entry: FirstpartyFeedEntry): VerifiedSignedDefinition {
    const { envelope } = entry;
    if (isBuiltinEnvelope(envelope)) {
      return {
        form: 'builtin',
        key: envelope.kind,
        definitionId: envelope.definitionId,
        revision: envelope.revision,
        definition: envelope.definition,
        definitionSha256: builtinDefinitionSha256(envelope.definition),
        signatureB64: entry.signatureB64,
      };
    }
    const { slot, definitionId, revision, definition } = envelope;
    return {
      form: 'slot',
      key: slot as FirstpartySourceKey,
      definitionId,
      revision,
      definition,
      definitionSha256: firstpartyDefinitionSha256(definition),
      signatureB64: entry.signatureB64,
      oauthClientSecretCiphertextB64: entry.oauthClientSecretCiphertextB64,
    };
  }

  // The name is a fleet-wide literal, never customer content; one that is neither a slot key nor a compiled-in kind is left out.
  private logRefusal(errorCode: EntryRefusal, name: string): void {
    const known = isFirstpartySourceKey(name) || builtinSpecKinds().includes(name);
    this.deps.logger.warn(
      'firstparty_definition_refused',
      known ? { errorCode, component: name } : { errorCode },
    );
  }
}
