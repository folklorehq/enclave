import { createHash } from 'node:crypto';

const SHA384_BYTES = 48;

// Synthetic PCR3/PCR4 model for binding checks; not AWS Nitro's measurement algorithm.
function deriveIdentityPcr(identity: string): Uint8Array {
  return createHash('sha384')
    .update(new Uint8Array(SHA384_BYTES))
    .update(identity, 'utf8')
    .digest();
}

export function derivePcr3FromRoleArn(roleArn: string): Uint8Array {
  return deriveIdentityPcr(roleArn);
}

export function derivePcr4FromInstanceId(instanceId: string): Uint8Array {
  return deriveIdentityPcr(instanceId);
}
