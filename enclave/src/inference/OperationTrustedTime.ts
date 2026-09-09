import { trustedTimeBindingV1Schema, type TrustedTimeBindingV1 } from '@folklore/contracts';
import type { TrustedTimeAuthorityPort } from '@folklore/inference';
import { TrustedTimeAuthority, type TrustedTimeAuthorityOptions } from './TrustedTimeAuthority.js';

/** A fresh attested checkpoint per operation, never a silent renewal of an in-flight checkpoint. */
export function createOperationTrustedTime(
  binding: TrustedTimeBindingV1,
  options: TrustedTimeAuthorityOptions,
): TrustedTimeAuthorityPort {
  const owned = trustedTimeBindingV1Schema.parse(binding);
  const authority = new TrustedTimeAuthority(options);
  let ready: Promise<void> | undefined;
  return {
    read: async (context) => {
      await (ready ??= authority.initialize(owned));
      return authority.read(context);
    },
  };
}
