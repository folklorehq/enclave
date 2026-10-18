import { randomBytes } from 'node:crypto';
import { SendMessageCommand, type SQSClient } from '@aws-sdk/client-sqs';
import { memberIdentityLinkOutputSchema, type MemberIdentityLinkOutput } from '@folklore/contracts';
import {
  enclaveOutputBindingForPayload,
  type EnclaveOutputAuthenticator,
  type EnclaveOutputIdentity,
} from '@folklore/contracts/enclave-output';
import { sha256Hex } from '@folklore/utils';
import { jsonOutputPayload } from '../tenant/output/json-output-payload.js';

const NONCE_BYTES = 32;
const DEDUPLICATION_ID_MAX = 128;
// The characters SQS accepts in a FIFO deduplication id.
const DEDUPLICATION_ID_CHARSET = /^[A-Za-z0-9!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]+$/;
const DEDUPLICATION_PREFIX = 'member-link';
const IDENTITY_CHANGED = 'member_link_output_identity_changed';

export interface MemberIdentityLinkEmitterDeps {
  readonly sqs: Pick<SQSClient, 'send'>;
  readonly processedQueueUrl: string;
  readonly outputAuthenticator: EnclaveOutputAuthenticator;
  readonly outputIdentity: () => EnclaveOutputIdentity;
}

/** Signs a confirmed member link and puts it on the pool's processed queue for the worker to apply. */
export class MemberIdentityLinkEmitter {
  constructor(private readonly deps: MemberIdentityLinkEmitterDeps) {}

  async emit(output: MemberIdentityLinkOutput): Promise<void> {
    const payload = memberIdentityLinkOutputSchema.parse(jsonOutputPayload(output));
    const identity = this.deps.outputIdentity();
    const envelope = this.deps.outputAuthenticator.sign(
      enclaveOutputBindingForPayload(payload, {
        ...identity,
        nonce: randomBytes(NONCE_BYTES).toString('hex'),
      }),
    );
    this.assertIdentityUnchanged(identity);
    await this.deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: this.deps.processedQueueUrl,
        MessageBody: JSON.stringify(envelope),
        MessageGroupId: payload.orgId,
        MessageDeduplicationId: this.deduplicationId(payload, identity.assignmentGeneration),
      }),
    );
  }

  private assertIdentityUnchanged(signed: EnclaveOutputIdentity): void {
    const current = this.deps.outputIdentity();
    if (
      current.deploymentId !== signed.deploymentId ||
      current.assignmentGeneration !== signed.assignmentGeneration
    ) {
      throw new Error(IDENTITY_CHANGED);
    }
  }

  private deduplicationId(output: MemberIdentityLinkOutput, generation: number): string {
    const readable = `${DEDUPLICATION_PREFIX}-${output.orgId}-${output.linkId}-${generation}`;
    if (readable.length <= DEDUPLICATION_ID_MAX && DEDUPLICATION_ID_CHARSET.test(readable)) {
      return readable;
    }
    return `${DEDUPLICATION_PREFIX}-${sha256Hex(readable)}`;
  }
}
