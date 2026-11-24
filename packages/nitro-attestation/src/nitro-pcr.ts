import { createHash } from 'node:crypto';

const SHA384_BYTES = 48;

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
